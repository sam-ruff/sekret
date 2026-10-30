//! Prints the SekretSecret CRD, for regenerating the Helm chart copy.

fn main() -> anyhow::Result<()> {
    print!("{}", sekret_operator::crd_yaml()?);
    Ok(())
}
