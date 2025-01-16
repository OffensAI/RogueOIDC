# RogueOIDC

This repository contains a minimal OpenID Connect (OIDC) Provider implementation using FastAPI and a Python script for AWS role assumption using OIDC authentication. The implementation is designed for demonstration and testing purposes.

## Components

1. **Rogue OIDC Provider** (`web-app/main.py`): A FastAPI-based web application that implements core OIDC functionality
2. **AWS Role Assumption Script** (`assume-role-script/assume_role-rogue-oidc.py`): A Python script that demonstrates the OIDC authentication flow and AWS role assumption

## Prerequisites

- Python 3.7+
- AWS Account with appropriate IAM role configuration
- SSL certificate and private key for the OIDC Provider
- EC2 instance or similar hosting environment

## Installation

Clone the repository and install the required python packages for each script. 

```bash
# The webserver will run on port 443 so the dependencies must be available for the root user as well
# You either install the packages as root or you install them globally

git clone https://github.com/OffensAI/RogueOIDC
cd RogueOIDC

virtualenv oidc
source oidc/bin/activate

# This command is just in case you want to run the assume role script from the same host as the Rogue OIDC
pip3 install -r requirements.txt

cd web-app
pip3 install -r requirements.txt
```

## Configuration

Only the OIDC Provider requires custom configuration. Update the `web-app/.env` with your own configuration:

```bash
# The domain where the OIDC is hosted
ISSUER=https://oidc.example.com
# The client id (this has to match the 'audience' set in AWS)
CLIENT_ID=demo_example
# Client secret for authentication
CLIENT_SECRET=change_me
# Supported redirect URI
REDIRECT_URI=https://oidc.example.com
# The subject value for the JWT that is used for AWS API call AssumeRoleWithWebIdentity 
SUBJECT=example
# Certificate files full path
SSL_KEYFILE=/etc/letsencrypt/live/oidc.example.com/privkey.pem
SSL_CERTFILE=/etc/letsencrypt/live/oidc.example.com/fullchain.pem
# Listening address
HOST=0.0.0.0
# Listening port
PORT=443
```

## Usage

### Starting the OIDC Provider

1. Run the OIDC provider:

```bash
# You need to run with admin privileges if you want to the app to listen on a port under 1000
python main.py
```

The server will start on `https://0.0.0.0` with SSL enabled if the configuration is using port 443 and provides valid certificates.

### Running the AWS Role Assumption Script

The script doesn't require AWS credentials to run. Use `--help` to get information about the available arguments.

```text
./assume-role-rogue-oidc.py --help
usage: assume-role-rogue-oidc.py [-h] --oidc-url OIDC_URL --client-id CLIENT_ID --client-secret CLIENT_SECRET --redirect-uri REDIRECT_URI --role-arn ROLE_ARN --role-session-name ROLE_SESSION_NAME

OIDC AWS role assumption script

options:
  -h, --help            show this help message and exit
  --oidc-url OIDC_URL   Rouge OIDC URL (e.g., https://oidc.example.com)
  --client-id CLIENT_ID
                        OIDC client ID
  --client-secret CLIENT_SECRET
                        OIDC client secret
  --redirect-uri REDIRECT_URI
                        OIDC redirect URI (e.g., https://oidc.example.com)
  --role-arn ROLE_ARN   ARN of OIDC AWS IAM role to assume
  --role-session-name ROLE_SESSION_NAME
                        This will appear as username in CloudTrail
```

Example usage:

```bash
cd assume-role-script
./asume-role-rogue-oidc.py --oidc-url https://oidc.example.com \
      --client-id demo_example \
      --client-secret change_me \
      --redirect-uri https://oidc.example.com/ \
      --role-arn arn:aws:iam::123456789012:role/oidc_role \
      --role-session-name demo_session
```

The script will:
1. Obtain an authorization code from the OIDC provider
2. Exchange the code for a JWT signed by the OIDC provider
3. Use the ID token to assume the specified AWS role
4. Test the credentials by doing an STS GetCallerIdentity

## API Endpoints

The OIDC Provider implements the following endpoints:

- `/.well-known/openid-configuration`: OIDC configuration endpoint
- `/jwks`: JSON Web Key Set endpoint
- `/auth`: Authorization endpoint
- `/token`: Token endpoint

## AWS IAM Configuration

To use this with AWS, you need to:

1. Create an IAM OIDC provider
2. Create an IAM role with a trust policy for the OIDC provider
3. Configure appropriate permissions for the role

Example trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::YOUR_ACCOUNT_ID:oidc-provider/your-domain"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "your-domain:aud": "demo-example"
        }
      }
    }
  ]
}
```

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## License

[MIT License](LICENSE)

## Disclaimer

This implementation is for demonstration purposes only. Don't use the implementation of the Rogue OIDC web application as a good example of implementing OIDC in a legitimate context.
