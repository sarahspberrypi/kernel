//! See <https://github.com/matklad/cargo-xtask/>.

mod arch;
mod archive;
mod artifact;
mod build;
mod cargo_build;
mod ci;
mod clippy;

use std::path::Path;

use anyhow::Result;
use clap::Parser;
use xshell::Shell;

#[derive(Parser)]
enum Cli {
	Build(build::Build),
	#[command(subcommand)]
	Ci(ci::Ci),
	Clippy(clippy::Clippy),
}

impl Cli {
	fn run(self) -> Result<()> {
		match self {
			Self::Build(build) => build.run(),
			Self::Ci(ci) => ci.run(),
			Self::Clippy(clippy) => clippy.run(),
		}
	}
}

fn main() -> Result<()> {
	let cli = Cli::parse();
	cli.run()
}

pub fn sh() -> Result<Shell> {
	let sh = Shell::new()?;
	let project_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
	sh.change_dir(project_root);
	Ok(sh)
}
