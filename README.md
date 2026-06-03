
```bash
# Build binwalk docker image
git clone --branch v3.1.0 https://github.com/ReFirmLabs/binwalk
cd binwalk
sudo docker build -t binwalkv3 .

# Create and activate conda env
conda create -f environment.yml -y
conda activate firmware-scanner

# Install firmware_scanner
pip install --no-deps .

# If developing install it as editable
pip install --no-deps -e .

# Set API key environment variable
export GEMINI_API_KEY=<YOUR_API_KEY_HERE>

# Scanner help
firmware-scanner -h
```
