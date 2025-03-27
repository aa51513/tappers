// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! (Non-Windows) TAP interfaces.

#![cfg(not(target_os = "windows"))]

use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, RawFd};

use crate::{AddAddress, DeviceState, Interface};

/// A handle to a TAP network interface.
///
/// This struct represents a TAP interface, and is the primary way to interact with TAP devices on
/// *nix platforms.
#[derive(Debug)]
pub struct Tap {
    name: Interface,
    fd: RawFd,
}

impl Tap {
    /// Creates a new TAP interface with a randomly assigned name.
    ///
    /// The interface is automatically deleted when the `Tap` struct is dropped.
    ///
    /// # Errors
    ///
    /// Any error returned by the operating system when creating the TAP interface.
    pub fn new() -> io::Result<Self> {
        // TODO: generate a random name
        Self::new_named(Interface::new("tap0")?)
    }

    /// Opens a TAP interface with the given name.
    ///
    /// If an interface with the given name does not exist, it will be created. The interface is
    /// automatically deleted when the `Tap` struct is dropped.
    ///
    /// # Errors
    ///
    /// Any error returned by the operating system when creating the TAP interface.
    pub fn new_named(name: Interface) -> io::Result<Self> {
        // TODO: implement
        todo!()
    }

    /// Sets the state of the device (up/down).
    ///
    /// # Errors
    ///
    /// Any error returned by the operating system when setting the device state.
    pub fn set_state(&mut self, state: DeviceState) -> io::Result<()> {
        // TODO: implement
        todo!()
    }

    /// Adds an IP address to the TAP interface.
    ///
    /// # Errors
    ///
    /// Any error returned by the operating system when adding the address.
    pub fn add_addr<A: Into<AddAddress>>(&self, addr: A) -> io::Result<()> {
        self.name.add_addr(addr)
    }

    /// Removes an IP address from the TAP interface.
    ///
    /// # Errors
    ///
    /// Any error returned by the operating system when removing the address.
    pub fn remove_addr(&self, addr: IpAddr) -> io::Result<()> {
        self.name.remove_addr(addr)
    }

    /// Receives a packet from the TAP interface.
    ///
    /// # Errors
    ///
    /// Any error returned by the operating system when receiving the packet.
    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // TODO: implement
        todo!()
    }

    /// Sends a packet to the TAP interface.
    ///
    /// # Errors
    ///
    /// Any error returned by the operating system when sending the packet.
    pub fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        // TODO: implement
        todo!()
    }
}

impl AsRawFd for Tap {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_names() {
        let tap1 = Tap::new().unwrap();
        let tap2 = Tap::new().unwrap();
        let tap3 = Tap::new().unwrap();

        let tap1_name = tap1.name().unwrap();
        let tap2_name = tap2.name().unwrap();
        let tap3_name = tap3.name().unwrap();

        assert!(tap1_name != tap2_name);
        assert!(tap1_name != tap3_name);
        assert!(tap2_name != tap3_name);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn given_name() {
        use std::ffi::CStr;

        let chosen_name = unsafe { CStr::from_ptr(b"feth24\0".as_ptr() as *const libc::c_char) };

        let iface = Interface::from_cstr(chosen_name).unwrap();
        let tun = Tap::new_named(iface).unwrap();
        let tun_iface = tun.name().unwrap();

        assert_eq!(chosen_name, tun_iface.name_cstr());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn given_name() {
        use std::ffi::CStr;

        let chosen_name = unsafe { CStr::from_ptr(b"tap24\0".as_ptr() as *const libc::c_char) };

        let iface = Interface::from_cstr(chosen_name).unwrap();
        let tap = Tap::new_named(iface).unwrap();
        let tap_iface = tap.name().unwrap();

        assert_eq!(chosen_name, tap_iface.name_cstr());
    }

    #[test]
    fn up_down() {
        let mut tap1 = Tap::new().unwrap();

        tap1.set_up().unwrap();
        tap1.set_down().unwrap();
    }

    #[test]
    fn exists() {
        let tap1 = Tap::new().unwrap();
        let tap1_name = tap1.name().unwrap();
        assert!(tap1_name.exists().unwrap());
    }

    #[test]
    fn not_exists() {
        use std::ffi::OsStr;
        let chosen_name = OsStr::new("tap24");
        let iface = Interface::new(chosen_name).unwrap();
        assert!(!iface.exists().unwrap());
    }

    #[test]
    fn not_persistent() {
        let tap1 = Tap::new().unwrap();

        let tap1_name = tap1.name().unwrap();
        drop(tap1);
        assert!(!tap1_name.exists().unwrap());
    }

    #[test]
    fn nonblocking_switch() {
        let mut tap = Tap::new().unwrap();

        assert_eq!(tap.nonblocking().unwrap(), false);
        tap.set_nonblocking(true).unwrap();
        assert_eq!(tap.nonblocking().unwrap(), true);
        tap.set_nonblocking(false).unwrap();
        assert_eq!(tap.nonblocking().unwrap(), false);
    }
}

#[cfg(test)]
mod tests_unix {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn add_ipv4() {
        let tap1 = Tap::new().unwrap();
        let ip1 = Ipv4Addr::new(10, 101, 0, 1);
        tap1.add_addr(ip1).unwrap();

        let addrs = tap1.addrs().unwrap();
        assert!(addrs.iter().any(|a| a.address() == ip1));
    }

    #[test]
    fn add_ipv4_multi() {
        let tap1 = Tap::new().unwrap();

        let ip1 = Ipv4Addr::new(10, 101, 0, 1);
        tap1.add_addr(ip1).unwrap();

        let ip2 = Ipv4Addr::new(10, 102, 0, 1);
        tap1.add_addr(ip2).unwrap();

        let addrs = tap1.addrs().unwrap();
        assert!(addrs.iter().any(|a| a.address() == ip1));
        assert!(addrs.iter().any(|a| a.address() == ip2));
    }

    #[test]
    fn add_ipv6() {
        let tap1 = Tap::new().unwrap();

        let ip1 = Ipv6Addr::new(32, 2, 3, 4, 5, 6, 7, 8);
        tap1.add_addr(ip1).unwrap();

        let addrs = tap1.addrs().unwrap();
        assert!(addrs.iter().any(|a| a.address() == ip1));
    }

    #[test]
    fn add_ipv6_multi() {
        let tap1 = Tap::new().unwrap();
        let ip1 = Ipv6Addr::new(32, 2, 3, 4, 5, 6, 7, 8);
        let ip2 = Ipv6Addr::new(32, 5, 3, 4, 5, 6, 7, 8);
        tap1.add_addr(ip1).unwrap();
        tap1.add_addr(ip2).unwrap();

        let addrs = tap1.addrs().unwrap();
        assert!(addrs.iter().any(|a| a.address() == ip1));
        assert!(addrs.iter().any(|a| a.address() == ip2));
    }

    #[test]
    fn add_ipv4_ipv6_multi() {
        let tap1 = Tap::new().unwrap();
        let ip1 = Ipv4Addr::new(10, 101, 0, 1);
        let ip2 = Ipv4Addr::new(10, 102, 0, 1);
        let ip3 = Ipv6Addr::new(32, 2, 3, 4, 5, 6, 7, 8);
        let ip4 = Ipv6Addr::new(32, 5, 3, 4, 5, 6, 7, 8);
        tap1.add_addr(ip1).unwrap();
        tap1.add_addr(ip2).unwrap();
        tap1.add_addr(ip3).unwrap();
        tap1.add_addr(ip4).unwrap();
        let addrs = tap1.addrs().unwrap();
        assert!(addrs.iter().any(|a| a.address() == ip1));
        assert!(addrs.iter().any(|a| a.address() == ip2));
        assert!(addrs.iter().any(|a| a.address() == ip3));
        assert!(addrs.iter().any(|a| a.address() == ip4));
    }

    #[test]
    fn remove_ipv4() {
        let tap1 = Tap::new().unwrap();
        let ipv4 = Ipv4Addr::new(10, 101, 0, 1);
        tap1.add_addr(IpAddr::V4(ipv4)).unwrap();
        tap1.remove_addr(IpAddr::V4(ipv4)).unwrap();
        let addrs = tap1.addrs().unwrap();
        assert!(!addrs.iter().any(|a| a.address() == ipv4));
    }

    #[test]
    fn remove_ipv4_multi() {
        let tap1 = Tap::new().unwrap();
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 101, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 102, 0, 1));
        tap1.add_addr(ip1).unwrap();
        tap1.add_addr(ip2).unwrap();
        tap1.remove_addr(ip1).unwrap();
        tap1.remove_addr(ip2).unwrap();
        let addrs = tap1.addrs().unwrap();
        assert!(!addrs.iter().any(|a| a.address() == ip1));
        assert!(!addrs.iter().any(|a| a.address() == ip2));
    }

    #[test]
    fn remove_ipv6() {
        let tap1 = Tap::new().unwrap();
        let ip1 = IpAddr::V6(Ipv6Addr::new(32, 2, 3, 4, 5, 6, 7, 8));
        tap1.add_addr(ip1).unwrap();
        tap1.remove_addr(ip1).unwrap();
        let addrs = tap1.addrs().unwrap();
        assert!(!addrs.iter().any(|a| a.address() == ip1));
    }

    #[test]
    fn remove_ipv6_multi() {
        let tap1 = Tap::new().unwrap();
        let ip1 = IpAddr::V6(Ipv6Addr::new(32, 2, 3, 4, 5, 6, 7, 8));
        let ip2 = IpAddr::V6(Ipv6Addr::new(2, 5, 3, 4, 5, 6, 7, 8));
        tap1.add_addr(ip1).unwrap();
        tap1.add_addr(ip2).unwrap();
        tap1.remove_addr(ip1).unwrap();
        tap1.remove_addr(ip2).unwrap();
        let addrs = tap1.addrs().unwrap();
        assert!(!addrs.iter().any(|a| a.address() == ip1));
    }

    #[test]
    fn remove_ipv4_ipv6_multi() {
        let tap1 = Tap::new().unwrap();
        let ip1 = IpAddr::V6(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8));
        let ip2 = IpAddr::V6(Ipv6Addr::new(2, 5, 3, 4, 5, 6, 7, 8));
        let ip3 = IpAddr::V4(Ipv4Addr::new(10, 101, 0, 1));
        let ip4 = IpAddr::V4(Ipv4Addr::new(10, 102, 0, 1));
        tap1.add_addr(ip1).unwrap();
        tap1.add_addr(ip2).unwrap();
        tap1.add_addr(ip3).unwrap();
        tap1.add_addr(ip4).unwrap();
        tap1.remove_addr(ip3).unwrap();
        tap1.remove_addr(ip1).unwrap();
        tap1.remove_addr(ip4).unwrap();
        tap1.remove_addr(ip2).unwrap();
        let addrs = tap1.addrs().unwrap();
        assert!(!addrs.iter().any(|a| a.address() == ip1));
        assert!(!addrs.iter().any(|a| a.address() == ip2));
        assert!(!addrs.iter().any(|a| a.address() == ip3));
        assert!(!addrs.iter().any(|a| a.address() == ip4));
    }
}
