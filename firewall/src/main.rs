use aya::{include_bytes_aligned, Ebpf};
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
use log::{info, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    env_logger::init();

    // Ładowanie skompilowanego bajtkodu eBPF z Data Plane
    // W środowisku produkcyjnym ścieżka będzie inna.
    let mut bpf = Ebpf::load_file("../target/bpfel-unknown-none/release/firewall-ebpf")?;

    // Inicjalizacja logowania z poziomu kernela (aya-log)
    if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
        warn!("Nie udało się zainicjować logowania eBPF: {}", e);
    }

    let program: &mut Xdp = bpf.program_mut("firewall").unwrap().try_into()?;
    program.load()?;

    // Podpięcie programu pod interfejs
    program.attach(&opt.iface, XdpFlags::default())
        .expect("Nie udało się podpiąć programu XDP do interfejsu");

    info!("Firewall załadowany na interfejsie: {}. Naciśnij Ctrl-C, aby zakończyć.", opt.iface);

    info!("Oczekiwanie na sygnał SIGINT...");
    signal::ctrl_c().await?;
    info!("Zamykanie...");

    Ok(())
}
