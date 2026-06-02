use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use copia::{Sync, SyncBuilder};
use log::*;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use tokio::io::AsyncWriteExt;

use crate::types::RemoteFileInfo;
pub(crate) async fn push_path(sftp: &SftpSession, local: &str, remote: &str) -> Result<()> {
    let metadata = tokio::fs::metadata(local)
        .await
        .with_context(|| format!("cannot stat local path: {}", local))?;
    if metadata.is_dir() {
        info!("SFTP push dir: {} -> {}", local, remote);
        let _ = sftp.create_dir(remote).await;
        let mut dir = tokio::fs::read_dir(local)
            .await
            .with_context(|| format!("cannot read local directory: {}", local))?;
        while let Some(entry) = dir.next_entry().await? {
            let name = entry.file_name().to_string_lossy().into_owned();
            Box::pin(push_path(
                sftp,
                &format!("{}/{}", local.trim_end_matches('/'), name),
                &format!("{}/{}", remote.trim_end_matches('/'), name),
            ))
            .await?;
        }
    } else {
        info!("SFTP push: {} -> {}", local, remote);
        let content = tokio::fs::read(local)
            .await
            .with_context(|| format!("cannot read local file: {}", local))?;
        let content_len = content.len();
        use tokio::io::AsyncWriteExt;
        let mut file = sftp
            .open_with_flags(
                remote,
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            )
            .await
            .with_context(|| format!("failed to open remote file: {}", remote))?;
        file.write_all(&content)
            .await
            .with_context(|| format!("failed to write remote file: {}", remote))?;
        file.flush().await.ok();
        info!(
            "SFTP push complete: {} -> {} ({} bytes)",
            local, remote, content_len
        );
    }
    Ok(())
}

pub(crate) async fn pull_path(sftp: &SftpSession, remote: &str, local: &str) -> Result<()> {
    match sftp.metadata(remote).await {
        Ok(meta) => {
            if meta.is_dir() {
                info!("SFTP pull dir: {} -> {}", remote, local);
                tokio::fs::create_dir_all(local)
                    .await
                    .with_context(|| format!("cannot create local directory: {}", local))?;
                let entries = sftp
                    .read_dir(remote)
                    .await
                    .with_context(|| format!("cannot read remote directory: {}", remote))?;
                for entry in entries {
                    let name = entry.file_name();
                    Box::pin(pull_path(
                        sftp,
                        &format!("{}/{}", remote.trim_end_matches('/'), name),
                        &format!("{}/{}", local.trim_end_matches('/'), name),
                    ))
                    .await?;
                }
            } else {
                info!("SFTP pull: {} -> {}", remote, local);
                let data = sftp
                    .read(remote)
                    .await
                    .with_context(|| format!("failed to read remote file: {}", remote))?;
                if let Some(parent) = std::path::Path::new(local).parent() {
                    tokio::fs::create_dir_all(parent)
                        .await
                        .with_context(|| format!("cannot create parent directory: {:?}", parent))?;
                }
                tokio::fs::write(local, &data)
                    .await
                    .with_context(|| format!("failed to write local file: {}", local))?;
                info!(
                    "SFTP pull complete: {} -> {} ({} bytes)",
                    remote,
                    local,
                    data.len()
                );
            }
        }
        Err(e) => bail!("cannot access remote path {}: {}", remote, e),
    }
    Ok(())
}

pub(crate) async fn list_remote_files(
    sftp: &SftpSession,
    path: &str,
) -> Result<HashMap<String, RemoteFileInfo>> {
    let mut files = HashMap::new();
    let entries = sftp
        .read_dir(path)
        .await
        .with_context(|| format!("cannot read remote directory: {}", path))?;
    for entry in entries {
        let name = entry.file_name();
        let full_path = format!("{}/{}", path.trim_end_matches('/'), name);
        // Stat each entry to determine type and metadata
        let stat = sftp
            .metadata(&full_path)
            .await
            .with_context(|| format!("cannot stat remote: {}", full_path))?;
        if stat.is_dir() {
            let sub = Box::pin(list_remote_files(sftp, &full_path)).await?;
            files.extend(sub);
        } else {
            let size = stat.size.unwrap_or(0);
            let mtime = stat.mtime.unwrap_or(0) as u64;
            files.insert(full_path, RemoteFileInfo { size, mtime });
        }
    }
    Ok(files)
}

pub(crate) async fn list_local_files(path: &str) -> Result<HashMap<String, RemoteFileInfo>> {
    let mut files = HashMap::new();
    let mut stack = vec![path.to_string()];
    while let Some(dir) = stack.pop() {
        let mut rd = tokio::fs::read_dir(&dir)
            .await
            .with_context(|| format!("cannot read directory: {}", dir))?;
        while let Some(entry) = rd.next_entry().await? {
            let name = entry.file_name().to_string_lossy().into_owned();
            let full = format!("{}/{}", dir.trim_end_matches('/'), name);
            if entry.file_type().await?.is_dir() {
                stack.push(full);
            } else {
                let meta = entry.metadata().await?;
                files.insert(
                    full,
                    RemoteFileInfo {
                        size: meta.len(),
                        mtime: meta
                            .modified()?
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                    },
                );
            }
        }
    }
    Ok(files)
}

pub(crate) async fn rsync_upload(
    sftp: &SftpSession,
    local_root: &str,
    remote_root: &str,
    opts: &[String],
) -> Result<()> {
    let mut delete_extra = false;
    let mut dry_run = false;
    let mut use_checksum = false;
    let mut excludes: Vec<String> = Vec::new();
    for opt in opts {
        if opt == "delete" {
            delete_extra = true;
        } else if opt == "dry-run" || opt == "dry_run" {
            dry_run = true;
        } else if opt == "checksum" {
            use_checksum = true;
        } else if let Some(pat) = opt.strip_prefix("exclude=") {
            excludes.push(pat.to_string());
        } else {
            warn!("unknown --rsync-opt: {}", opt);
        }
    }
    // Ensure remote root directory exists
    let _ = sftp.create_dir(remote_root).await;

    let local_files = list_local_files(local_root).await?;
    let remote_files = list_remote_files(sftp, remote_root).await?;
    let local_prefix = local_root.trim_end_matches('/');
    let remote_prefix = remote_root.trim_end_matches('/');

    for (local_path, info) in &local_files {
        let rel_path = local_path.strip_prefix(local_prefix).unwrap_or(local_path);
        let rel_path = rel_path.strip_prefix('/').unwrap_or(rel_path);
        // --rsync-opt exclude
        if excludes.iter().any(|pat| {
            rel_path.contains(pat) || rel_path.ends_with(pat) || local_path.contains(pat)
        }) {
            info!("rsync skip (excluded): {}", rel_path);
            continue;
        }
        let remote_path = format!("{}/{}", remote_prefix, rel_path);

        match remote_files.get(&remote_path) {
            Some(ri) if ri.size == info.size && (!use_checksum && ri.mtime == info.mtime) => {
                info!("rsync skip (same): {}", rel_path);
                continue;
            }
            Some(ri) if ri.size == info.size => {
                info!("rsync delta check: {} (size={})", rel_path, info.size);
                let local_data = tokio::fs::read(local_path).await?;
                let remote_data = sftp.read(&remote_path).await?;
                if local_data == remote_data {
                    info!("rsync: content identical, skipping");
                    continue;
                }
                let sync = SyncBuilder::new().block_size(4096).build();
                let sig = sync.signature(std::io::Cursor::new(&remote_data))?;
                let delta = sync.delta(std::io::Cursor::new(&local_data), &sig)?;
                // Estimate savings: delta's total literal + copy data vs original size
                let delta_size = delta
                    .ops
                    .iter()
                    .map(|op| match op {
                        copia::DeltaOp::Literal(data) => data.len() as u64,
                        copia::DeltaOp::Copy { .. } => 13,
                    })
                    .sum::<u64>();
                if delta_size < local_data.len() as u64 {
                    info!(
                        "rsync delta: {} -> {} bytes (saved {}%)",
                        local_data.len(),
                        delta_size,
                        (1.0 - delta_size as f64 / local_data.len() as f64) * 100.0
                    );
                    let mut output = Vec::new();
                    sync.patch(std::io::Cursor::new(&remote_data), &delta, &mut output)?;
                    let mut file = sftp.create(&remote_path).await?;
                    file.write_all(&output).await?;
                    file.flush().await?;
                    continue;
                }
            }
            _ => {}
        }
        if dry_run {
            info!(
                "rsync dry-run: would upload {} -> {}",
                local_path, remote_path
            );
            continue;
        }
        info!("rsync upload: {} -> {}", local_path, remote_path);
        let data = tokio::fs::read(local_path).await?;
        let mut file = sftp.create(&remote_path).await?;
        file.write_all(&data).await?;
        file.flush().await?;
    }
    // --rsync-opt delete: remove remote files not in local
    if delete_extra {
        for remote_path in remote_files.keys() {
            let rel_path = remote_path
                .strip_prefix(remote_prefix)
                .unwrap_or(remote_path);
            let rel_path = rel_path.strip_prefix('/').unwrap_or(rel_path);
            // Check if this remote file has a matching local file
            let local_path = format!("{}/{}", local_prefix, rel_path);
            if !local_files.contains_key(&local_path) {
                if dry_run {
                    info!("rsync dry-run: would delete {}", remote_path);
                } else {
                    info!("rsync delete: {}", remote_path);
                    let _ = sftp.remove_file(remote_path).await;
                }
            }
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub(crate) async fn rsync_download(
    sftp: &SftpSession,
    remote_root: &str,
    local_root: &str,
) -> Result<()> {
    let local_files = list_local_files(local_root).await?;
    let remote_files = list_remote_files(sftp, remote_root).await?;
    let local_prefix = local_root.trim_end_matches('/');
    let remote_prefix = remote_root.trim_end_matches('/');

    for (remote_path, info) in &remote_files {
        let rel_path = remote_path
            .strip_prefix(remote_prefix)
            .unwrap_or(remote_path);
        let rel_path = rel_path.strip_prefix('/').unwrap_or(rel_path);
        let local_path = format!("{}/{}", local_prefix, rel_path);

        match local_files.get(&local_path) {
            Some(li) if li.size == info.size && li.mtime == info.mtime => {
                info!("rsync skip (same): {}", rel_path);
                continue;
            }
            Some(li) if li.size == info.size => {
                info!("rsync delta check: {}", rel_path);
                let local_data = tokio::fs::read(&local_path).await?;
                let remote_data = sftp.read(remote_path).await?;
                if local_data == remote_data {
                    info!("rsync: content identical");
                    continue;
                }
            }
            _ => {}
        }
        info!("rsync download: {} -> {}", remote_path, local_path);
        let data = sftp.read(remote_path).await?;
        if let Some(parent) = std::path::Path::new(&local_path).parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&local_path, &data).await?;
    }
    Ok(())
}
