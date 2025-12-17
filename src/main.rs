use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use pcap::{Capture, Device};
use pnet::datalink;
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ipv4::Ipv4Packet,
    Packet,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    symbols::Marker, // 引入 Marker 用于盲文显示
    text::{Line, Span},
    widgets::{
        canvas::{Canvas, Line as CanvasLine}, // 引入 Canvas 和 CanvasLine
        Block, Borders, Cell, Paragraph, Row, Table,
    },
    Terminal,
};
use std::{
    collections::{HashMap, VecDeque},
    error::Error,
    io,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

// ----------------------
// 常量定义
// ----------------------
const TICK_RATE_MS: u64 = 500;
const HISTORY_WINDOW_SECS: u64 = 60;
// 计算历史记录长度：60秒 / 0.5秒 = 120个点
const MAX_SAMPLES: usize = (HISTORY_WINDOW_SECS * 1000 / TICK_RATE_MS) as usize;

// ----------------------
// 数据结构
// ----------------------

struct SharedStats {
    traffic_delta: HashMap<Ipv4Addr, u64>,
    rx_delta: u64,
    tx_delta: u64,
}

struct IpHistory {
    samples: VecDeque<u64>,
    total_sum: u64,
}

impl IpHistory {
    fn new() -> Self {
        Self {
            samples: VecDeque::with_capacity(MAX_SAMPLES),
            total_sum: 0,
        }
    }

    fn update(&mut self, bytes: u64) -> f64 {
        self.samples.push_back(bytes);
        self.total_sum += bytes;
        if self.samples.len() > MAX_SAMPLES {
            if let Some(removed) = self.samples.pop_front() {
                self.total_sum -= removed;
            }
        }
        let duration_secs = self.samples.len() as f64 * (TICK_RATE_MS as f64 / 1000.0);
        if duration_secs == 0.0 {
            0.0
        } else {
            self.total_sum as f64 / duration_secs
        }
    }
}

struct App {
    // 历史数据
    rx_history: Vec<f64>, // 改为 f64 以便 Canvas 绘制
    tx_history: Vec<f64>,

    total_rx_bytes: u64,
    total_tx_bytes: u64,
    peak_rx_rate: u64,
    peak_tx_rate: u64,

    ip_histories: HashMap<Ipv4Addr, IpHistory>,
    top_talkers: Vec<(Ipv4Addr, f64)>,
    last_tick: Instant,
}

impl App {
    fn new() -> App {
        // 初始化填满 0，防止图表一开始是空的
        App {
            rx_history: vec![0.0; MAX_SAMPLES],
            tx_history: vec![0.0; MAX_SAMPLES],
            total_rx_bytes: 0,
            total_tx_bytes: 0,
            peak_rx_rate: 0,
            peak_tx_rate: 0,
            ip_histories: HashMap::new(),
            top_talkers: vec![],
            last_tick: Instant::now(),
        }
    }

    fn on_tick(&mut self, shared_stats: &Arc<Mutex<SharedStats>>) {
        let mut stats = shared_stats.lock().unwrap();

        // 1. 更新全局图表数据 (转为 f64)
        self.rx_history.remove(0);
        self.rx_history.push(stats.rx_delta as f64);
        self.tx_history.remove(0);
        self.tx_history.push(stats.tx_delta as f64);

        self.total_rx_bytes += stats.rx_delta;
        self.total_tx_bytes += stats.tx_delta;

        if stats.rx_delta > self.peak_rx_rate {
            self.peak_rx_rate = stats.rx_delta;
        }
        if stats.tx_delta > self.peak_tx_rate {
            self.peak_tx_rate = stats.tx_delta;
        }

        // 2. 更新 IP 排行榜
        let mut all_ips: Vec<Ipv4Addr> = self.ip_histories.keys().cloned().collect();
        for k in stats.traffic_delta.keys() {
            if !self.ip_histories.contains_key(k) {
                all_ips.push(*k);
            }
        }

        let mut current_snapshot = Vec::new();
        for ip in all_ips {
            let bytes_in = *stats.traffic_delta.get(&ip).unwrap_or(&0);
            let history = self.ip_histories.entry(ip).or_insert_with(IpHistory::new);
            let avg_bps = history.update(bytes_in);
            if history.total_sum > 0 {
                current_snapshot.push((ip, avg_bps));
            } else {
                self.ip_histories.remove(&ip);
            }
        }
        current_snapshot.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        self.top_talkers = current_snapshot;

        stats.traffic_delta.clear();
        stats.rx_delta = 0;
        stats.tx_delta = 0;
    }
}

fn get_local_ip(device_name: &str) -> Option<Ipv4Addr> {
    let interfaces = datalink::interfaces();
    let iface = interfaces.into_iter().find(|i| i.name == device_name)?;
    iface.ips.iter().find_map(|ip| {
        if let pnet::ipnetwork::IpNetwork::V4(net) = ip {
            Some(net.ip())
        } else {
            None
        }
    })
}

fn main() -> Result<(), Box<dyn Error>> {
    let device = Device::lookup()?.ok_or("No default device found")?;
    let device_name = device.name.clone();
    let local_ip = get_local_ip(&device_name).unwrap_or(Ipv4Addr::new(0, 0, 0, 0));

    let mut cap = Capture::from_device(device)?
        .promisc(true)
        .snaplen(65535)
        .timeout(10)
        .open()?;

    let stats = Arc::new(Mutex::new(SharedStats {
        traffic_delta: HashMap::new(),
        rx_delta: 0,
        tx_delta: 0,
    }));
    let stats_clone = Arc::clone(&stats);

    thread::spawn(move || loop {
        if let Ok(packet) = cap.next_packet() {
            if let Some(ethernet) = EthernetPacket::new(packet.data) {
                if ethernet.get_ethertype() == EtherTypes::Ipv4 {
                    if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                        let len = packet.header.len as u64;
                        let src = ipv4.get_source();
                        let dst = ipv4.get_destination();

                        let mut s = stats_clone.lock().unwrap();
                        if src == local_ip {
                            s.tx_delta += len;
                        } else {
                            s.rx_delta += len;
                        }

                        if is_lan_ip(&src) {
                            *s.traffic_delta.entry(src).or_insert(0) += len;
                        }
                        if is_lan_ip(&dst) {
                            *s.traffic_delta.entry(dst).or_insert(0) += len;
                        }
                    }
                }
            }
        }
    });

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let app = App::new();
    let res = run_app(&mut terminal, app, stats, &device_name);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err)
    }
    Ok(())
}

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    mut app: App,
    stats: Arc<Mutex<SharedStats>>,
    device_name: &str,
) -> io::Result<()> {
    let tick_rate = Duration::from_millis(TICK_RATE_MS);

    loop {
        terminal.draw(|f| {
            let main_chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(0)
                .constraints([Constraint::Length(16), Constraint::Min(10)].as_ref())
                .split(f.size());

            // --- Net Box ---
            let net_block = Block::default()
                .borders(Borders::ALL)
                .title(format!(" net [{}] ", device_name))
                .border_type(ratatui::widgets::BorderType::Rounded) // 圆角边框，像 btop
                .border_style(Style::default().fg(Color::White));
            f.render_widget(net_block.clone(), main_chunks[0]);

            let inner_area = net_block.inner(main_chunks[0]);
            let graph_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(70), Constraint::Percentage(30)].as_ref())
                .split(inner_area);

            // --- 关键修改：Canvas 绘图区域 ---
            let chart_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                .split(graph_chunks[0]);

            // 计算Y轴上限，让图表看起来饱满
            // 获取历史数据中的最大值，如果太小则设定一个最小值防止除以0
            let max_rx = app.rx_history.iter().cloned().fold(1.0, f64::max);
            let max_tx = app.tx_history.iter().cloned().fold(1.0, f64::max);
            
            // X轴长度 = 历史记录数量
            let x_limit = app.rx_history.len() as f64;

            // 1. Download Canvas
            let download_canvas = Canvas::default()
                .block(Block::default().title("Download").title_style(Style::default().fg(Color::Red)))
                .marker(Marker::Braille) // 核心：使用盲文点阵
                .x_bounds([0.0, x_limit])
                .y_bounds([0.0, max_rx]) // 动态Y轴
                .paint(|ctx| {
                    for (i, &val) in app.rx_history.iter().enumerate() {
                        // 绘制竖线，营造填充效果
                        // 从 y=0 画到 y=val
                        ctx.draw(&CanvasLine {
                            x1: i as f64,
                            y1: 0.0,
                            x2: i as f64,
                            y2: val,
                            color: Color::Red,
                        });
                    }
                });
            f.render_widget(download_canvas, chart_chunks[0]);

            // 2. Upload Canvas
            let upload_canvas = Canvas::default()
                .block(Block::default().title("Upload").title_style(Style::default().fg(Color::Blue)))
                .marker(Marker::Braille)
                .x_bounds([0.0, x_limit])
                .y_bounds([0.0, max_tx])
                .paint(|ctx| {
                    for (i, &val) in app.tx_history.iter().enumerate() {
                        ctx.draw(&CanvasLine {
                            x1: i as f64,
                            y1: 0.0,
                            x2: i as f64,
                            y2: val,
                            color: Color::Blue,
                        });
                    }
                });
            f.render_widget(upload_canvas, chart_chunks[1]);

            // --- 右侧文字统计 ---
            let text_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                .split(graph_chunks[1]);

            let current_rx_bps = (*app.rx_history.last().unwrap_or(&0.0)) * (1000.0 / TICK_RATE_MS as f64);
            let current_tx_bps = (*app.tx_history.last().unwrap_or(&0.0)) * (1000.0 / TICK_RATE_MS as f64);
            let peak_rx_bps = (app.peak_rx_rate as f64) * (1000.0 / TICK_RATE_MS as f64);
            let peak_tx_bps = (app.peak_tx_rate as f64) * (1000.0 / TICK_RATE_MS as f64);

            let rx_text = vec![
                Line::from(vec![Span::raw("▼ "), Span::styled(format_bps(current_rx_bps), Style::default().fg(Color::White).add_modifier(Modifier::BOLD))]),
                Line::from(vec![Span::styled("  Top: ", Style::default().fg(Color::DarkGray)), Span::raw(format_bps(peak_rx_bps))]),
                Line::from(vec![Span::styled("  Tot: ", Style::default().fg(Color::DarkGray)), Span::raw(format_bytes_total(app.total_rx_bytes))]),
            ];
            let rx_info = Paragraph::new(rx_text).block(Block::default().style(Style::default().fg(Color::Red)));
            f.render_widget(rx_info, text_chunks[0]);

            let tx_text = vec![
                Line::from(vec![Span::raw("▲ "), Span::styled(format_bps(current_tx_bps), Style::default().fg(Color::White).add_modifier(Modifier::BOLD))]),
                Line::from(vec![Span::styled("  Top: ", Style::default().fg(Color::DarkGray)), Span::raw(format_bps(peak_tx_bps))]),
                Line::from(vec![Span::styled("  Tot: ", Style::default().fg(Color::DarkGray)), Span::raw(format_bytes_total(app.total_tx_bytes))]),
            ];
            let tx_info = Paragraph::new(tx_text).block(Block::default().style(Style::default().fg(Color::Blue)));
            f.render_widget(tx_info, text_chunks[1]);

            // --- 底部表格 ---
            let header_cells = ["IP Address", "Avg Bandwidth (1 min)", "Status"].iter().map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow)));
            let header = Row::new(header_cells).style(Style::default().bg(Color::Rgb(50, 50, 50))).height(1).bottom_margin(1);
            let rows = app.top_talkers.iter().take(20).map(|(ip, bps)| {
                let color = if *bps > 1_000_000.0 { Color::Red } else if *bps > 10_000.0 { Color::LightYellow } else { Color::Green };
                Row::new(vec![Cell::from(ip.to_string()), Cell::from(format_bps(*bps)).style(Style::default().fg(color)), Cell::from("Active")]).height(1)
            });
            let table = Table::new(rows, [Constraint::Percentage(40), Constraint::Percentage(40), Constraint::Percentage(20)])
                .header(header)
                .block(Block::default().title(" Local Network Users ").borders(Borders::ALL).border_type(ratatui::widgets::BorderType::Rounded));
            f.render_widget(table, main_chunks[1]);
        })?;

        let timeout = tick_rate.checked_sub(app.last_tick.elapsed()).unwrap_or_else(|| Duration::from_secs(0));
        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') || key.code == KeyCode::Char('c') { return Ok(()); }
            }
        }
        if app.last_tick.elapsed() >= tick_rate {
            app.on_tick(&stats);
            app.last_tick = Instant::now();
        }
    }
}

fn is_lan_ip(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    (octets[0] == 192 && octets[1] == 168) || (octets[0] == 10)
}

fn format_bps(bps: f64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * KB;
    if bps >= MB { format!("{:.2} Mb/s", bps * 8.0 / MB) }
    else if bps >= KB { format!("{:.2} Kb/s", bps * 8.0 / KB) }
    else { format!("{:.0} b/s", bps * 8.0) }
}

fn format_bytes_total(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if bytes >= GB { format!("{:.2} GiB", bytes as f64 / GB as f64) }
    else if bytes >= MB { format!("{:.2} MiB", bytes as f64 / MB as f64) }
    else if bytes >= KB { format!("{:.2} KiB", bytes as f64 / KB as f64) }
    else { format!("{} B", bytes) }
}
