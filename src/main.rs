use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use pcap::{Capture, Device};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ipv4::Ipv4Packet,
    Packet,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Cell, Row, Sparkline, Table},
    Terminal,
};
use std::{
    collections::HashMap,
    error::Error,
    io,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

// ----------------------
// 数据结构
// ----------------------

// 用于在线程间共享的统计数据
struct SharedStats {
    // IP -> 字节数 (本周期的累计)
    traffic_map: HashMap<Ipv4Addr, u64>,
    // 总流量 (本周期的累计)
    total_bytes: u64,
}

// UI 状态 App
struct App {
    // 历史数据，用于画图 (Sparkline)
    traffic_history: Vec<u64>,
    // 排行榜快照
    top_talkers: Vec<(Ipv4Addr, u64)>,
    // 上一次更新的时间
    last_tick: Instant,
}

impl App {
    fn new() -> App {
        App {
            traffic_history: vec![0; 100], // 保留最近100个点的历史
            top_talkers: vec![],
            last_tick: Instant::now(),
        }
    }

    // 每一帧更新数据
    fn on_tick(&mut self, shared_stats: &Arc<Mutex<SharedStats>>) {
        let mut stats = shared_stats.lock().unwrap();

        // 1. 更新总流量历史图表
        // 将当前周期的总流量存入历史
        self.traffic_history.remove(0);
        self.traffic_history.push(stats.total_bytes);

        // 2. 更新排行榜
        let mut sorted: Vec<(Ipv4Addr, u64)> = stats.traffic_map.iter().map(|(k, v)| (*k, *v)).collect();
        // 按流量降序
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        self.top_talkers = sorted;

        // 3. 重要：清空统计数据，开始下一个统计周期
        // 这样我们显示的才是“实时速率”而不是“累计总量”
        stats.traffic_map.clear();
        stats.total_bytes = 0;
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    // 1. 设置网络抓包
    let device = Device::lookup()?.ok_or("No default device found")?;
    let device_name = device.name.clone();

    let mut cap = Capture::from_device(device)?
        .promisc(true)
        .snaplen(65535)
        .timeout(10) // timeout 短一点，防止阻塞抓包线程
        .open()?;

    let stats = Arc::new(Mutex::new(SharedStats {
        traffic_map: HashMap::new(),
        total_bytes: 0,
    }));
    let stats_clone = Arc::clone(&stats);

    // 2. 启动抓包线程
    thread::spawn(move || {
        loop {
            if let Ok(packet) = cap.next_packet() {
                if let Some(ethernet) = EthernetPacket::new(packet.data) {
                    if ethernet.get_ethertype() == EtherTypes::Ipv4 {
                        if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                            let len = packet.header.len as u64;
                            let src = ipv4.get_source();
                            let dst = ipv4.get_destination();

                            let mut s = stats_clone.lock().unwrap();
                            s.total_bytes += len;

                            // 统计逻辑：局域网内监控通常关心谁在大量发包或收包
                            // 这里简单地将流量加到源IP和目的IP上
                            if is_lan_ip(&src) {
                                *s.traffic_map.entry(src).or_insert(0) += len;
                            }
                            if is_lan_ip(&dst) {
                                *s.traffic_map.entry(dst).or_insert(0) += len;
                            }
                        }
                    }
                }
            }
        }
    });

    // 3. 设置 TUI 环境 (Ratatui)
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // 4. 运行 UI 循环
    let app = App::new();
    let res = run_app(&mut terminal, app, stats, &device_name);

    // 5. 恢复终端
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err)
    }

    Ok(())
}

// 主 UI 循环
fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    mut app: App,
    stats: Arc<Mutex<SharedStats>>,
    device_name: &str,
) -> io::Result<()> {
    let tick_rate = Duration::from_millis(500); // 0.5秒刷新一次界面

    loop {
        terminal.draw(|f| {
            // --- 布局定义 ---
            // 垂直切分：上部分是图表，下部分是列表
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints(
                    [
                        Constraint::Length(12), // 图表高度
                        Constraint::Min(10),    // 列表占据剩余
                    ]
                    .as_ref(),
                )
                .split(f.size());

            // --- 顶部：总流量波形图 (Sparkline) ---
            let history_u64 = &app.traffic_history;
            // 将历史数据标准化以便显示（Sparkline需要u64，但为了显示效果，我们取相对高度）
            // 这里直接用原始字节数，ratatui 会自动处理比例
            
            let sparkline = Sparkline::default()
                .block(
                    Block::default()
                        .title(format!(" Total Network Traffic (Monitor: {}) ", device_name))
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Cyan)), // 青色边框
                )
                .data(history_u64)
                .style(Style::default().fg(Color::Magenta)); // 像 btop 一样的洋红色线条

            f.render_widget(sparkline, chunks[0]);

            // --- 底部：排行榜表格 (Table) ---
            let header_cells = ["IP Address", "Role", "Bandwidth"]
                .iter()
                .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
            let header = Row::new(header_cells)
                .style(Style::default().bg(Color::Rgb(50, 50, 50))) // 深灰色表头背景
                .height(1)
                .bottom_margin(1);

            let rows = app.top_talkers.iter().take(20).map(|(ip, bytes)| {
                // 将字节转换为易读格式
                let speed = format_speed(*bytes, tick_rate); 
                
                // 简单的颜色逻辑：流量特别大显示红色
                let color = if *bytes > 1_000_000 { Color::Red } else { Color::Green };
                
                let cells = vec![
                    Cell::from(ip.to_string()),
                    Cell::from("LAN Device"),
                    Cell::from(speed).style(Style::default().fg(color)),
                ];
                Row::new(cells).height(1)
            });

            let table = Table::new(
                rows,
                [
                    Constraint::Percentage(40),
                    Constraint::Percentage(30),
                    Constraint::Percentage(30),
                ]
            )
            .header(header)
            .block(
                Block::default()
                    .title(" Top Bandwidth Consumers ")
                    .borders(Borders::ALL)
                    .border_type(ratatui::widgets::BorderType::Rounded) // 圆角边框
                    .border_style(Style::default().fg(Color::White)),
            );

            f.render_widget(table, chunks[1]);
        })?;

        // --- 事件处理 ---
        let timeout = tick_rate
            .checked_sub(app.last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if let KeyCode::Char('q') = key.code {
                    return Ok(());
                }
                if let KeyCode::Char('c') = key.code {
                    // Ctrl+C 也可以退出
                    return Ok(());
                }
            }
        }

        if app.last_tick.elapsed() >= tick_rate {
            app.on_tick(&stats);
            app.last_tick = Instant::now();
        }
    }
}

// 辅助：判断局域网 IP (根据你的环境修改)
fn is_lan_ip(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 常见局域网网段: 192.168.x.x, 10.x.x.x, 172.16-31.x.x
    (octets[0] == 192 && octets[1] == 168) && octets[2] == 5
}

// 辅助：格式化速度
fn format_speed(bytes: u64, duration: Duration) -> String {
    let secs = duration.as_secs_f64();
    if secs == 0.0 { return "0 B/s".to_string(); }
    
    let bytes_per_sec = bytes as f64 / secs;
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * KB;

    if bytes_per_sec >= MB {
        format!("{:.2} MB/s", bytes_per_sec / MB)
    } else if bytes_per_sec >= KB {
        format!("{:.2} KB/s", bytes_per_sec / KB)
    } else {
        format!("{:.0} B/s", bytes_per_sec)
    }
}
