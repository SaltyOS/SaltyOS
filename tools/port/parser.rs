//! .port file parser
//! SPDX-License-Identifier: GPL-2.0-only

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
pub enum BuildType {
    Autotools,
    CMake,
    Meson,
    Make,
    Custom,
    Targets,
    Cargo,
}

#[derive(Debug, Clone)]
pub struct Target {
    pub name: String,
    pub sources: Vec<String>,
    pub extra_flags: Vec<String>,
}

/// A static library to build before targets.
#[derive(Debug, Clone)]
pub struct LibTarget {
    pub name: String,
    pub sources: Vec<String>,
    pub extra_flags: Vec<String>,
}

pub struct PortConfig {
    pub name: String,
    pub version: String,
    pub description: String,
    pub homepage: String,
    pub license: String,
    pub source_url: String,
    pub source_subdir: String,
    pub source_sha256: String,
    pub depends_build: Vec<String>,
    pub depends_runtime: Vec<String>,
    pub options: HashMap<String, bool>,
    pub build_type: BuildType,
    pub configure_args: Vec<String>,
    pub prepare_script: String,
    pub install_map: Vec<(String, String)>,
    pub env_overrides: HashMap<String, String>,
    pub autoconf_cache: Vec<(String, String)>,
    pub libs: Vec<LibTarget>,
    pub targets: Vec<Target>,
    pub targets_cflags: String,
}

impl Default for PortConfig {
    fn default() -> Self {
        PortConfig {
            name: String::new(),
            version: String::new(),
            description: String::new(),
            homepage: String::new(),
            license: String::new(),
            source_url: String::new(),
            source_subdir: String::new(),
            source_sha256: "SKIP".to_string(),
            depends_build: Vec::new(),
            depends_runtime: Vec::new(),
            options: HashMap::new(),
            build_type: BuildType::Autotools,
            configure_args: Vec::new(),
            prepare_script: String::new(),
            install_map: Vec::new(),
            env_overrides: HashMap::new(),
            autoconf_cache: Vec::new(),
            libs: Vec::new(),
            targets: Vec::new(),
            targets_cflags: String::new(),
        }
    }
}

impl fmt::Display for PortConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Port: {} {}", self.name, self.version)?;
        writeln!(f, "Description: {}", self.description)?;
        writeln!(f, "Homepage: {}", self.homepage)?;
        writeln!(f, "License: {}", self.license)?;
        writeln!(f, "Source: {}", self.source_url)?;
        if !self.source_subdir.is_empty() {
            writeln!(f, "Source subdir: {}", self.source_subdir)?;
        }
        writeln!(f, "SHA256: {}", self.source_sha256)?;
        writeln!(f, "Build type: {:?}", self.build_type)?;
        if !self.configure_args.is_empty() {
            writeln!(f, "Configure args:")?;
            for arg in &self.configure_args {
                writeln!(f, "  {}", arg)?;
            }
        }
        if !self.targets.is_empty() {
            writeln!(f, "Targets:")?;
            for t in &self.targets {
                writeln!(f, "  {} = {}", t.name, t.sources.join(" "))?;
            }
        }
        if !self.install_map.is_empty() {
            writeln!(f, "Install mappings:")?;
            for (src, dst) in &self.install_map {
                writeln!(f, "  {} -> {}", src, dst)?;
            }
        }
        Ok(())
    }
}

pub fn parse_port_file(path: &Path) -> Result<PortConfig, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Cannot read {}: {}", path.display(), e))?;

    let mut config = PortConfig::default();
    let mut current_section = String::new();
    let mut multiline_key = String::new();

    for (line_num, raw_line) in content.lines().enumerate() {
        let line_num = line_num + 1;
        let line = raw_line;

        // Skip empty lines and comments
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Section header
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current_section = trimmed[1..trimmed.len() - 1].to_string();
            multiline_key.clear();
            continue;
        }

        // Continuation line (starts with whitespace)
        if line.starts_with(' ') || line.starts_with('\t') {
            let value = trimmed.to_string();
            match current_section.as_str() {
                "build" if multiline_key == "configure" => {
                    config.configure_args.push(value);
                }
                "prepare" => {
                    if !config.prepare_script.is_empty() {
                        config.prepare_script.push('\n');
                    }
                    config.prepare_script.push_str(trimmed);
                }
                "install" => {
                    // Continuation lines in install are additional mappings
                    if let Some((src, dst)) = trimmed.split_once('=') {
                        config.install_map.push((
                            src.trim().to_string(),
                            dst.trim().to_string(),
                        ));
                    }
                }
                "targets.cflags" => {
                    // Continuation lines: append with space
                    if !config.targets_cflags.is_empty() {
                        config.targets_cflags.push(' ');
                    }
                    config.targets_cflags.push_str(trimmed);
                }
                _ => {}
            }
            continue;
        }

        // Key = value pair
        if let Some((key, value)) = trimmed.split_once('=') {
            let key = key.trim();
            let value = value.trim();
            multiline_key = key.to_string();

            match current_section.as_str() {
                "port" => match key {
                    "name" => config.name = value.to_string(),
                    "version" => config.version = value.to_string(),
                    "description" => config.description = value.to_string(),
                    "homepage" => config.homepage = value.to_string(),
                    "license" => config.license = value.to_string(),
                    _ => eprintln!("Warning: unknown key [port].{} at line {}", key, line_num),
                },
                "source" => match key {
                    "url" => config.source_url = value.to_string(),
                    "subdir" => config.source_subdir = value.to_string(),
                    "sha256" => config.source_sha256 = value.to_string(),
                    _ => eprintln!("Warning: unknown key [source].{} at line {}", key, line_num),
                },
                "depends" => match key {
                    "build" => {
                        config.depends_build = value
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                    }
                    "runtime" => {
                        config.depends_runtime = value
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                    }
                    _ => eprintln!("Warning: unknown key [depends].{} at line {}", key, line_num),
                },
                "options" => {
                    config.options.insert(
                        key.to_string(),
                        value == "true" || value == "yes" || value == "1",
                    );
                }
                "build" => match key {
                    "type" => {
                        config.build_type = match value {
                            "autotools" => BuildType::Autotools,
                            "cmake" => BuildType::CMake,
                            "meson" => BuildType::Meson,
                            "make" => BuildType::Make,
                            "custom" => BuildType::Custom,
                            "targets" => BuildType::Targets,
                            "cargo" => BuildType::Cargo,
                            _ => {
                                return Err(format!(
                                    "Unknown build type '{}' at line {}",
                                    value, line_num
                                ))
                            }
                        };
                    }
                    "configure" => {
                        // Value may be empty (args follow on continuation lines)
                        if !value.is_empty() {
                            config.configure_args.push(value.to_string());
                        }
                    }
                    _ => eprintln!("Warning: unknown key [build].{} at line {}", key, line_num),
                },
                "prepare" => {
                    // In prepare section, key=value lines are shell commands too
                    if !config.prepare_script.is_empty() {
                        config.prepare_script.push('\n');
                    }
                    config.prepare_script.push_str(trimmed);
                }
                "install" => {
                    config.install_map.push((
                        key.to_string(),
                        value.trim().to_string(),
                    ));
                }
                "env" => {
                    config.env_overrides.insert(
                        key.to_string(),
                        value.to_string(),
                    );
                }
                "autoconf_cache" => {
                    config.autoconf_cache.push((
                        key.to_string(),
                        value.to_string(),
                    ));
                }
                "libs" => {
                    // name = src1.c src2.c :: -Dflag -Ipath
                    let (sources_part, extra_part) = if let Some((s, e)) = value.split_once("::") {
                        (s.trim(), e.trim())
                    } else {
                        (value, "")
                    };
                    let sources: Vec<String> = sources_part
                        .split_whitespace()
                        .map(|s| s.to_string())
                        .collect();
                    let extra_flags: Vec<String> = if extra_part.is_empty() {
                        Vec::new()
                    } else {
                        extra_part
                            .split_whitespace()
                            .map(|s| s.to_string())
                            .collect()
                    };
                    config.libs.push(LibTarget {
                        name: key.to_string(),
                        sources,
                        extra_flags,
                    });
                }
                "targets" => {
                    // name = src1.c src2.c :: -Dflag -Ipath
                    let (sources_part, extra_part) = if let Some((s, e)) = value.split_once("::") {
                        (s.trim(), e.trim())
                    } else {
                        (value, "")
                    };
                    let sources: Vec<String> = sources_part
                        .split_whitespace()
                        .map(|s| s.to_string())
                        .collect();
                    let extra_flags: Vec<String> = if extra_part.is_empty() {
                        Vec::new()
                    } else {
                        extra_part
                            .split_whitespace()
                            .map(|s| s.to_string())
                            .collect()
                    };
                    config.targets.push(Target {
                        name: key.to_string(),
                        sources,
                        extra_flags,
                    });
                }
                "targets.cflags" => {
                    // Non-indented line in [targets.cflags]: start or append
                    if !config.targets_cflags.is_empty() {
                        config.targets_cflags.push(' ');
                    }
                    config.targets_cflags.push_str(trimmed);
                }
                _ => eprintln!("Warning: unknown section [{}] at line {}", current_section, line_num),
            }
            continue;
        }

        // Lines without '=' — could be prepare script or targets.cflags
        match current_section.as_str() {
            "prepare" => {
                if !config.prepare_script.is_empty() {
                    config.prepare_script.push('\n');
                }
                config.prepare_script.push_str(trimmed);
            }
            "targets.cflags" => {
                if !config.targets_cflags.is_empty() {
                    config.targets_cflags.push(' ');
                }
                config.targets_cflags.push_str(trimmed);
            }
            _ => {}
        }
    }

    // Validate required fields
    if config.name.is_empty() {
        return Err("Missing required field: [port].name".to_string());
    }
    if config.version.is_empty() {
        return Err("Missing required field: [port].version".to_string());
    }

    Ok(config)
}
