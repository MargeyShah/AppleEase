import base64
import time
import json
import os
import requests
import jwt
from pathlib import Path
from appleease.utils import get_days_from_now

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import pkcs12

from dotenv import load_dotenv


ASC_BASE = 'https://api.appstoreconnect.apple.com/v1'

def init(env_file: Path):
    expiry_date = get_days_from_now()
    load_dotenv(dotenv_path=env_file)
    directory_path = os.getenv('OUT_DIR', 'out')

    os.makedirs(directory_path, exist_ok=True)

    return {
        # App Store Connect API key
        'ISSUER_ID': os.getenv('ISSUER_ID'),
        'KEY_ID': os.getenv('KEY_ID'),

        # Apple AppStoreConnect Generated Private Key 
        'P8_KEY_PATH': os.getenv('P8_FILE'),

        # App/Bundle ID to target (must already exist and have capabilities set)
        'BUNDLE_ID_IDENTIFIER': os.getenv('BUNDLE_ID'),

        # Mobile Provision Profile Details
        'PROFILE_TYPE': 'IOS_APP_ADHOC',  # IOS_APP_DEVELOPMENT, IOS_APP_ADHOC, IOS_APP_STORE
        'PROFILE_NAME': f'Through-{expiry_date}',

        # CSR subject info
        'CSR_COMMON_NAME': os.getenv('CN'),
        'CSR_EMAIL': os.getenv('EMAIL'),

        # Crypto params
        'RSA_KEY_SIZE': 2048,
        'P12_PASSWORD': os.getenv('P12_PASS'),

        # Output files
        'OUT_PRIVATE_KEY_PEM': f"{os.getenv('OUT_DIR')}/private_key.pem",
        'OUT_CSR_PEM': f"{os.getenv('OUT_DIR')}/certificate_signing_request.csr",
        'OUT_CERT_CER': f"{os.getenv('OUT_DIR')}/apple_certificate.cer",
        'OUT_CERT_PEM': f"{os.getenv('OUT_DIR')}/apple_certificate.pem",
        'OUT_P12': f"{os.getenv('OUT_DIR')}/through-{expiry_date}-cert.p12",
        'OUT_MOBILEPROVISION': f"{os.getenv('OUT_DIR')}/through-{expiry_date}.mobileprovision",
    }



# =========================
# ====== UTILITIES ========
# =========================

def make_jwt(issuer_id: str, key_id: str, p8_path: str) -> str:
    private_key = Path(p8_path).read_text()
    now = int(time.time())
    return jwt.encode(
        {'iss': issuer_id, 'iat': now, 'exp': now + 20 * 60, 'aud': 'appstoreconnect-v1'},
        private_key,
        algorithm='ES256',
        headers={'kid': key_id, 'alg': 'ES256'}
    )

def asc_request(token: str, method: str, url: str, params=None, payload=None):
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    r = requests.request(method, url, headers=headers, params=params, json=payload, timeout=60)
    if not r.ok:
        try:
            detail = r.json()
        except Exception:
            detail = r.text
        raise RuntimeError(f'ASC {method} {url} failed: {r.status_code} {r.reason}\n{detail}')
    return r.json()

def asc_paged(token: str, first_url: str, params=None):
    results = []
    url = first_url
    while url:
        data = asc_request(token, 'GET', url, params=params)
        results.extend(data.get('data', []))
        url = data.get('links', {}).get('next')
        params = None  # next already contains query
    return results

# =========================
# === CRYPTO: CSR/KEY =====
# =========================

def generate_rsa_key_and_csr(cn: str, email: str | None, key_bits: int):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    name_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if email:
        name_attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
    subject = x509.Name(name_attrs)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, hashes.SHA256())
    )
    return private_key, csr

def save_private_key_pem(private_key, path: str):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    Path(path).write_bytes(pem)

def save_csr_pem(csr, path: str):
    pem = csr.public_bytes(serialization.Encoding.PEM)
    Path(path).write_bytes(pem)

# =========================
# === CERTIFICATE + P12 ===
# =========================

def create_certificate_from_csr(token: str, csr_pem_str: str, cert_type: str):
    payload = {
        'data': {
            'type': 'certificates',
            'attributes': {
                'certificateType': cert_type,  # IOS_DEVELOPMENT or IOS_DISTRIBUTION
                'csrContent': csr_pem_str
            }
        }
    }
    res = asc_request(token, 'POST', f'{ASC_BASE}/certificates', payload=payload)
    cert_id = res['data']['id']
    cert_b64 = res['data']['attributes']['certificateContent']
    cert_der = base64.b64decode(cert_b64)
    return cert_id, cert_der

def write_cert_files(cert_der: bytes, cer_path: str, pem_path: str):
    # .cer is typically DER; also write PEM for convenience
    Path(cer_path).write_bytes(cert_der)
    cert = x509.load_der_x509_certificate(cert_der)
    pem = cert.public_bytes(serialization.Encoding.PEM)
    Path(pem_path).write_bytes(pem)

def create_p12(private_key, cert_der: bytes, password: str | None, p12_path: str):
    cert = x509.load_der_x509_certificate(cert_der)
    name = b'Apple Cert'
    enc = serialization.NoEncryption() if not password else serialization.BestAvailableEncryption(password.encode('utf-8'))
    p12_bytes = pkcs12.serialize_key_and_certificates(
        name=name,
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=enc
    )
    Path(p12_path).write_bytes(p12_bytes)

# =========================
# == DEVICES / BUNDLE ID ==
# =========================

def get_bundle_id_id(token: str, identifier: str) -> str:
    params = {'filter[identifier]': identifier}
    res = asc_request(token, 'GET', f'{ASC_BASE}/bundleIds', params=params)
    items = res.get('data', [])
    if not items:
        raise RuntimeError(f'Bundle ID not found: {identifier}')
    return items[0]['id']

def get_all_enabled_ios_device_ids(token: str):
    # platform=IOS returns iPhone/iPad/Apple TV/Apple Watch; filter ENABLED
    params = {
        'filter[platform]': 'IOS',
        'filter[status]': 'ENABLED',
        'limit': 200
    }
    devices = asc_paged(token, f'{ASC_BASE}/devices', params=params)
    allowed_classes = {'IPHONE', 'IPAD'}
    devices = [d for d in devices if d.get('attributes', {}).get('deviceClass') in allowed_classes]
    
    return [d['id'] for d in devices ]

# =========================
# ===== PROFILES API ======
# =========================

def create_profile(token: str, name: str, profile_type: str, bundle_id_id: str, certificate_ids: list[str], device_ids: list[str] | None):
    relationships = {
        'bundleId': {'data': {'type': 'bundleIds', 'id': bundle_id_id}},
        'certificates': {'data': [{'type': 'certificates', 'id': cid} for cid in certificate_ids]}
    }
    # Devices only for development or ad hoc profiles
    if profile_type in ('IOS_APP_DEVELOPMENT', 'IOS_APP_ADHOC'):
        relationships['devices'] = {'data': [{'type': 'devices', 'id': did} for did in (device_ids or [])]}

    payload = {
        'data': {
            'type': 'profiles',
            'attributes': {
                'name': name,
                'profileType': profile_type
            },
            'relationships': relationships
        }
    }
    res = asc_request(token, 'POST', f'{ASC_BASE}/profiles', payload=payload)
    prof_b64 = res['data']['attributes']['profileContent']
    return base64.b64decode(prof_b64)

