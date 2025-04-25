# Secure Coding

## Tiny Secondhand Shopping Platform.

You should add some functions and complete the security requirements.

## requirements

if you don't have a miniconda(or anaconda), you can install it on this url. - https://docs.anaconda.com/free/miniconda/index.html

```
git clone https://github.com/ggam-yong/whs-secure-coding.git
conda env create -f enviroments.yaml
```


## usage

run the server process.

```
cd whs-secure-coding 
conda activate whs-secure-coding
pip install -r requirements.txt # 의존성
python app.py
```

if you want to test on external machine, you can utilize the ngrok to forwarding the url.
```
# optional
sudo snap install ngrok
ngrok http 5000
```

## admin id/pw
ID : admin
pw : 123456
