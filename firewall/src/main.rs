use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;
use clap::Parser;
use log::{info, warn};
use std::net::Ipv4Addr;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,

    #[clap(short, long)]
    block_ip: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    env_logger::init();

    let mut bpf = Ebpf::load_file("../target/bpfel-unknown-none/release/firewall-ebpf")?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
        warn!("Nie udało się zainicjować logowania eBPF: {}", e);
    }

    let program: &mut Xdp = bpf.program_mut("firewall").unwrap().try_into()?;
    program.load()?;
    program
        .attach(&opt.iface, XdpFlags::default())
        .expect("Nie udało się podpiąć programu XDP do interfejsu");

    info!("Firewall załadowany na interfejsie: {}", opt.iface);

    let mut blocklist: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;

    if let Some(ip_str) = opt.block_ip {
        let ipv4_adder = ip_str.parse::<Ipv4Addr>().unwrap();
        let ip_u32 = u32::from(ipv4_adder);
        blocklist.insert(ip_u32, 1, 0)?;
        info!("Blocklist: {}", ipv4_adder);
    }

    info!("Oczekiwanie na sygnał SIGINT...");
    signal::ctrl_c().await?;
    info!("Zamykanie...");

    Ok(())
}
