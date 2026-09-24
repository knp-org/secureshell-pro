//! OpenSSH's atomic replacement extension, which ssh2 0.9 does not expose.
//! Use a separate SFTP channel on the verified session. Never fall back to
//! deleting the destination: servers without the extension must fail safely.
use std::io::{Read, Write};

const EXTENSION: &[u8] = b"posix-rename@openssh.com";

fn put_string(packet: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    let len = u32::try_from(value.len()).map_err(|_| "SFTP string too long")?;
    packet.extend_from_slice(&len.to_be_bytes());
    packet.extend_from_slice(value);
    Ok(())
}
fn take_string<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], String> {
    if input.len() < 4 {
        return Err("Truncated SFTP response".into());
    }
    let len = u32::from_be_bytes(input[..4].try_into().unwrap()) as usize;
    *input = &input[4..];
    if input.len() < len {
        return Err("Truncated SFTP string".into());
    }
    let (value, rest) = input.split_at(len);
    *input = rest;
    Ok(value)
}
fn send(channel: &mut ssh2::Channel, packet: &[u8]) -> Result<(), String> {
    channel
        .write_all(&(packet.len() as u32).to_be_bytes())
        .map_err(|e| e.to_string())?;
    channel.write_all(packet).map_err(|e| e.to_string())?;
    channel.flush().map_err(|e| e.to_string())
}
fn receive(channel: &mut ssh2::Channel) -> Result<Vec<u8>, String> {
    let mut len = [0; 4];
    channel.read_exact(&mut len).map_err(|e| e.to_string())?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > 65536 {
        return Err("Invalid SFTP packet length".into());
    }
    let mut packet = vec![0; len];
    channel.read_exact(&mut packet).map_err(|e| e.to_string())?;
    Ok(packet)
}

pub(super) fn replace(
    session: &ssh2::Session,
    source: &str,
    destination: &str,
) -> Result<(), String> {
    let mut channel = session.channel_session().map_err(|e| e.to_string())?;
    channel.subsystem("sftp").map_err(|e| e.to_string())?;
    send(&mut channel, &[1, 0, 0, 0, 3])?; // SSH_FXP_INIT, version 3
    let version = receive(&mut channel)?;
    if version.len() < 5 || version[0] != 2 || version[1..5] != 3u32.to_be_bytes() {
        return Err("Unsupported SFTP version for atomic replacement".into());
    }
    let mut extensions = &version[5..];
    let mut supported = false;
    while !extensions.is_empty() {
        let name = take_string(&mut extensions)?;
        let value = take_string(&mut extensions)?;
        supported |= name == EXTENSION && value == b"1";
    }
    if !supported {
        return Err("Server does not support atomic replacement; original file retained".into());
    }
    let mut request = vec![200, 0, 0, 0, 1]; // SSH_FXP_EXTENDED, request 1
    put_string(&mut request, EXTENSION)?;
    put_string(&mut request, source.as_bytes())?;
    put_string(&mut request, destination.as_bytes())?;
    send(&mut channel, &request)?;
    let status = receive(&mut channel)?;
    if status.len() < 9 || status[0] != 101 || status[1..5] != 1u32.to_be_bytes() {
        return Err("Invalid atomic rename response".into());
    }
    let code = u32::from_be_bytes(status[5..9].try_into().unwrap());
    if code != 0 {
        return Err(format!(
            "Atomic replacement failed (SFTP status {code}); original file retained"
        ));
    }
    let _ = channel.send_eof();
    let _ = channel.close();
    Ok(())
}
