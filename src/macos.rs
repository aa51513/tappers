// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! MacOS-specific TUN/TAP interfaces.
//!

mod feth;
mod utun;

use std::io;

pub use feth::FethTap;
pub use utun::Utun;

use std::net::IpAddr;
#[cfg(not(target_os = "windows"))]
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};

use crate::{AddAddress, AddressInfo, DeviceState, Interface};

pub(crate) struct TunImpl {
    tun: Utun,
}

impl TunImpl {
    #[inline]
    pub fn new() -> io::Result<Self> {
        Ok(Self { tun: Utun::new()? })
    }

    #[inline]
    pub fn new_named(if_name: Interface) -> io::Result<Self> {
        Ok(Self {
            tun: Utun::new_named(if_name)?,
        })
    }

    #[inline]
    pub fn addrs(&self) -> io::Result<Vec<AddressInfo>> {
        self.tun.addrs()
    }

    #[inline]
    pub fn add_addr<A: Into<AddAddress>>(&self, req: A) -> io::Result<()> {
        self.tun.add_addr(req)
    }

    #[inline]
    pub fn remove_addr(&self, addr: IpAddr) -> io::Result<()> {
        self.tun.remove_addr(addr)
    }

    #[inline]
    pub fn name(&self) -> io::Result<Interface> {
        self.tun.name()
    }

    #[inline]
    pub fn set_state(&mut self, state: DeviceState) -> io::Result<()> {
        self.tun.set_state(state)
    }

    #[inline]
    pub fn mtu(&self) -> io::Result<usize> {
        self.tun.mtu()
    }

    #[inline]
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.tun.set_nonblocking(nonblocking)
    }

    #[inline]
    pub fn nonblocking(&self) -> io::Result<bool> {
        self.tun.nonblocking()
    }

    #[inline]
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.tun.send(buf)
    }

    #[inline]
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.tun.recv(buf)
    }
}

#[cfg(not(target_os = "windows"))]
impl AsFd for TunImpl {
    fn as_fd(&self) -> BorrowedFd {
        self.tun.as_fd()
    }
}

#[cfg(not(target_os = "windows"))]
impl AsRawFd for TunImpl {
    fn as_raw_fd(&self) -> RawFd {
        self.tun.as_raw_fd()
    }
}

pub(crate) struct TapImpl {
    tap: FethTap,
}

impl TapImpl {
    #[inline]
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            tap: FethTap::new()?,
        })
    }

    #[inline]
    pub fn new_named(if_name: Interface) -> io::Result<Self> {
        Ok(Self {
            tap: FethTap::new_named(Some(if_name), None)?,
        })
    }

    #[inline]
    pub fn addrs(&self) -> io::Result<Vec<AddressInfo>> {
        self.tap.addrs()
    }

    #[inline]
    pub fn add_addr<A: Into<AddAddress>>(&self, req: A) -> io::Result<()> {
        self.tap.add_addr(req)
    }

    #[inline]
    pub fn remove_addr(&self, addr: IpAddr) -> io::Result<()> {
        self.tap.remove_addr(addr)
    }

    #[inline]
    pub fn name(&self) -> io::Result<Interface> {
        self.tap.name()
    }

    #[inline]
    pub fn set_state(&mut self, state: DeviceState) -> io::Result<()> {
        self.tap.set_state(state)
    }

    #[inline]
    pub fn mtu(&self) -> io::Result<usize> {
        self.tap.mtu()
    }

    #[inline]
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.tap.set_nonblocking(nonblocking)
    }

    #[inline]
    pub fn nonblocking(&self) -> io::Result<bool> {
        self.tap.nonblocking()
    }

    #[inline]
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.tap.send(buf)
    }

    #[inline]
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.tap.recv(buf)
    }
}

#[cfg(not(target_os = "windows"))]
impl AsFd for TapImpl {
    fn as_fd(&self) -> BorrowedFd {
        self.tap.as_fd()
    }
}

#[cfg(not(target_os = "windows"))]
impl AsRawFd for TapImpl {
    fn as_raw_fd(&self) -> RawFd {
        self.tap.as_raw_fd()
    }
}
