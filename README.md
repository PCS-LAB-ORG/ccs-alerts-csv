# Download a CSV alert report from Prisma Cloud

Simple python 3 script to initiate and download a CSV report of all config/build alerts from the last X days.

To get started:

```
export PRISMA_API_URL=<your value>
export PRISMA_ACCESS_KEY_ID=<your value>
export PRISMA_SECRET_KEY=<your value>

# Very first run
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

python3 get-ccs-alerts.py

```
Your CSV report will be saved in the current directory and it will have a filename of `alerts-<current date and time>.csv`. You will also get an export of all Prisma Cloud Code Security policies in a json format as `build_policies.json`.