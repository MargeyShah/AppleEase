import click
from dotenv import load_dotenv
from appleease.main import *
from appleease.utils import cleanup_output_files

REMOVABLE_OUTPUTS = ['OUT_PRIVATE_KEY_PEM', 'OUT_CSR_PEM', 'OUT_CERT_CER', 'OUT_CERT_PEM']

@click.group()
def cli():
    """appleease helper."""

@cli.command()
@click.option('-e', '--env-file', type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True), required=True)
def run(env_file: Path):
    cfg = init(env_file=env_file)

    load_dotenv(dotenv_path=env_file)
    
    print(os.getenv('P8_FILE'))
    print(cfg['OUT_PRIVATE_KEY_PEM'])

    # Decide certificate type from profile type if not obvious
    if cfg['PROFILE_TYPE'] == 'IOS_APP_DEVELOPMENT':
        certificate_type = 'IOS_DEVELOPMENT'
    else:
        certificate_type = 'IOS_DISTRIBUTION'  # for ADHOC or APP_STORE

    click.echo('Creating JWT...')
    token = make_jwt(cfg['ISSUER_ID'], cfg['KEY_ID'], cfg['P8_KEY_PATH'])

    click.echo('Generating RSA key and CSR...')
    priv_key, csr = generate_rsa_key_and_csr(cfg['CSR_COMMON_NAME'], cfg['CSR_EMAIL'], cfg['RSA_KEY_SIZE'])
    save_private_key_pem(priv_key, cfg['OUT_PRIVATE_KEY_PEM'])
    save_csr_pem(csr, cfg['OUT_CSR_PEM'])
    csr_pem_str = Path(cfg['OUT_CSR_PEM']).read_text()

    click.echo(f'Requesting Apple {certificate_type} certificate...')
    cert_id, cert_der = create_certificate_from_csr(token, csr_pem_str, certificate_type)
    write_cert_files(cert_der, cfg['OUT_CERT_CER'], cfg['OUT_CERT_PEM'])
    click.echo(f'Certificate created: {cert_id}')
    click.echo(f' - Saved {cfg["OUT_CERT_CER"]} (DER) and {cfg["OUT_CERT_PEM"]} (PEM)')

    click.echo('Creating PKCS#12 (.p12)...')
    create_p12(priv_key, cert_der, cfg['P12_PASSWORD'], cfg['OUT_P12'])
    click.echo(f' - Saved {cfg["OUT_P12"]}')

    click.echo('Looking up Bundle ID...')
    bundle_id_id = get_bundle_id_id(token, cfg['BUNDLE_ID_IDENTIFIER'])
    click.echo(f' - Bundle ID id: {bundle_id_id}')

    device_ids = None
    if cfg['PROFILE_TYPE'] in ('IOS_APP_DEVELOPMENT', 'IOS_APP_ADHOC'):
        click.echo('Fetching all ENABLED iOS devices...')
        device_ids = get_all_enabled_ios_device_ids(token)
        click.echo(f' - Found {len(device_ids)} devices')

    click.echo(f'Creating provisioning profile: {cfg["PROFILE_NAME"]} ({cfg["PROFILE_TYPE"]})...')
    profile_bytes = create_profile (
       token=token,
        name=cfg['PROFILE_NAME'],
        profile_type=cfg['PROFILE_TYPE'],
        bundle_id_id=bundle_id_id,
        certificate_ids=[cert_id],
        device_ids=device_ids
    )
    Path(cfg['OUT_MOBILEPROVISION']).write_bytes(profile_bytes)

    # remove unneeded csr, cer, pem files
    cleanup_output_files([Path(cfg[item]) for item in REMOVABLE_OUTPUTS])
    click.echo(f' - Saved {cfg["OUT_MOBILEPROVISION"]}')
    click.echo('Done.')

