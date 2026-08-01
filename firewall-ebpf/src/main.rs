#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use core::ptr::read_unaligned;

const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = 14;

#[xdp]
pub fn firewall(ctx: XdpContext) -> u32 {
    match try_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let data = ctx.data() as usize;
    let data_end = ctx.data_end() as usize;

    if data + ETH_HDR_LEN > data_end {
        return Err(());
    }

    let ethertype_ptr = (data + 12) as *const u16;

    let ethertype = u16::from_be(unsafe { core::ptr::read_unaligned(ethertype_ptr) });

    if ethertype == ETH_P_IP {
        info!(&ctx, "Otrzymano pakiet IPv4!");

        if data + 34 > data_end {
            return Ok(xdp_action::XDP_PASS);
        }
        let src_ip_ptr = (data + 26) as *const u32;
        let src_ip = u32::from_be(unsafe { core::ptr::read_unaligned(src_ip_ptr) });
        // info!(&ctx, "Source IP: {:i}", src_ip); // Format {:i} to bajer aya-log do ładnego drukowania IP
    }

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
