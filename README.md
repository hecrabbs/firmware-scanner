
```bash
# Build binwalk docker image
git clone --branch v3.1.0 https://github.com/ReFirmLabs/binwalk
cd binwalk
sudo docker build -t binwalkv3 .

# Create and activate conda env
conda create -f environment.yml -y
conda activate firmware-scanner

# If developing install firmware_scanner as editable
pip install -e .

# Scanner help
firmware_scanner -h
```
