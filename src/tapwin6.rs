// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://opensource.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! (Windows) TAP and simulated TUN interfaces provided by the `tap-windows6` OpenVPN driver.

#![cfg(target_os = "windows")]
#![cfg(feature = "tapwin6")]

use std::io;
use std::mem;
use std::net::IpAddr;
use std::os::windows::io::{AsRawSocket, RawSocket};
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Networking::WinSock::{
    ioctlsocket, recv, send, socket, AF_INET, FIONBIO, INVALID_SOCKET, SIO_GET_INTERFACE_LIST,
    SOCK_RAW, SOL_SOCKET, SO_ERROR, WSASocketW, WSA_FLAG_OVERLAPPED,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

use crate::{AddAddress, DeviceState, Interface};

const TAP_WIN_IOCTL_GET_VERSION: u32 = 0x220004;
const TAP_WIN_IOCTL_GET_MTU: u32 = 0x220018;
const TAP_WIN_IOCTL_GET_INFO: u32 = 0x22000C;
const TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT_IP: u32 = 0x220007;
const TAP_WIN_IOCTL_SET_MEDIA_STATUS: u32 = 0x220006;
const TAP_WIN_IOCTL_GET_LOG_LINE: u32 = 0x22000A;
const TAP_WIN_IOCTL_CONFIG_DHCP_MASQ: u32 = 0x220009;
const TAP_WIN_IOCTL_GET_MAC: u32 = 0x220010;
const TAP_WIN_IOCTL_GET_GUID: u32 = 0x220012;
const TAP_WIN_IOCTL_GET_TUN_NAME: u32 = 0x220014;

/// A handle to a TAP network interface.
///
/// This struct represents a TAP interface and is the primary way to interact with TAP devices on
/// Windows platforms using the `tap-windows6` driver.
#[derive(Debug)]
pub struct Tap {
    name: Interface,
    socket: RawSocket,
    handle: HANDLE,
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
        // Convert interface name to a format suitable for DeviceIoControl
        let mut device_path = format!("\\\\.\\\\Global\\\\{}\\.tap", name.name()); // TODO: verify this is correct
        let device_path_utf16: Vec<u16> = device_path.encode_utf16().collect();

        // Open a handle to the TAP adapter
        let handle = unsafe {
            windows_sys::Win32::Storage::FileSystem::CreateFileW(
                device_path_utf16.as_ptr(),
                windows_sys::Win32::Foundation::GENERIC_READ
                    | windows_sys::Win32::Foundation::GENERIC_WRITE,
                0,
                ptr::null_mut(),
                windows_sys::Win32::Foundation::OPEN_EXISTING,
                windows_sys::Win32::Foundation::FILE_ATTRIBUTE_SYSTEM
                    | windows_sys::Win32::System::IO::FILE_FLAG_OVERLAPPED,
                INVALID_HANDLE_VALUE,
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }

        // Create a socket for sending/receiving data
        let socket = unsafe {
            WSASocketW(
                AF_INET as i32, // AF_INET or AF_PACKET
                SOCK_RAW as i32, // SOCK_RAW or SOCK_DGRAM
                0,
                ptr::null_mut(),
                0,
                WSA_FLAG_OVERLAPPED,
            )
        };

        if socket == windows_sys::Win32::Networking::WinSock::INVALID_SOCKET {
            unsafe { CloseHandle(handle) };
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            name,
            socket: socket as RawSocket,
            handle,
        })
    }

    /// Sets the state of the device (up/down).
    ///
    /// # Errors
    ///
    /// Any error returned by the operating system when setting the device state.
    pub fn set_state(&mut self, state: DeviceState) -> io::Result<()> {
        let status: u32 = match state {
            DeviceState::Up => 1,   // TRUE
            DeviceState::Down => 0, // FALSE
        };

        let mut bytes_returned: u32 = 0;

        let result = unsafe {
            DeviceIoControl(
                self.handle,
                TAP_WIN_IOCTL_SET_MEDIA_STATUS,
                ptr::addr_of(status) as *mut _,
                mem::size_of::<u32>() as u32,
                ptr::null_mut(),
                0,
                ptr::addr_of_mut(bytes_returned),
                ptr::null_mut(),
            )
        };

        if result == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
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
        let result = unsafe {
            recv(
                self.socket as _,
                buf.as_mut_ptr() as *mut _,
                buf.len() as i32,
                0,
            )
        };

        if result == windows_sys::Win32::Networking::WinSock::SOCKET_ERROR {
            let err = unsafe { GetLastError() };
            return Err(io::Error::from_raw_os_error(err as i32));
        }

        Ok(result as usize)
    }

    /// Sends a packet to the TAP interface.
    ///
    /// # Errors
    ///
    /// Any error returned by the operating system when sending the packet.
    pub fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        let result = unsafe {
            send(
                self.socket as _,
                buf.as_ptr() as *const _,
                buf.len() as i32,
                0,
            )
        };

        if result == windows_sys::Win32::Networking::WinSock::SOCKET_ERROR {
            let err = unsafe { GetLastError() };
            return Err(io::Error::from_raw_os_error(err as i32));
        }

        Ok(result as usize)
    }
}

impl AsRawSocket for Tap {
    fn as_raw_socket(&self) -> RawSocket {
        self.socket
    }
}

impl Drop for Tap {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Networking::WinSock::closesocket(self.socket as _);
            CloseHandle(self.handle);
        }
    }
}
