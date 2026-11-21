"""Optional acquisition of pinned public files for Linux x86_64. No inference or uploads."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
from urllib.request import Request, urlopen

FILES = {
    "engine.tar.gz": ("https://github.com/ggml-org/llama.cpp/releases/download/b8058/llama-b8058-bin-ubuntu-x64.tar.gz",
                      24643738, "e796372ebd3a30636050a2479da6a48b732ba1acf46b1b97e15c2ad667782357"),
    "model.gguf": ("https://huggingface.co/QuantFactory/SmolLM2-135M-Instruct-GGUF/resolve/476854d00ede130660aba430d15f9347ad2e7d0e/SmolLM2-135M-Instruct.Q4_K_M.gguf",
                   105454144, "8030f04528538d47bda434f6f0bdf3952c40a58123e4d5e755332f23731a8684")}
MODEL_ID="QuantFactory/SmolLM2-135M-Instruct-GGUF@476854d00ede130660aba430d15f9347ad2e7d0e/SmolLM2-135M-Instruct.Q4_K_M.gguf"


def retrieve(directory, item):
    name,(url,size,expected)=item
    part=directory/(name+".part")
    if (directory/name).exists():
        with (directory/name).open("rb") as f:
            if hashlib.file_digest(f,"sha256").hexdigest()==expected:return
        raise ValueError("existing file differs from pinned digest: "+name)
    digest=hashlib.sha256();n=0
    with urlopen(Request(url,headers={"User-Agent":"SPE-reference-reader"}),timeout=120) as src,part.open("wb") as dst:
        while data:=src.read(1024*1024):
            n+=len(data)
            if n>size:raise ValueError("unexpected response size")
            dst.write(data);digest.update(data)
    if n!=size or digest.hexdigest()!=expected:raise ValueError("download differs from pinned artifact: "+name)
    part.replace(directory/name)


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("directory",type=Path);a=p.parse_args()
    a.directory.mkdir(parents=True,exist_ok=True)
    with ThreadPoolExecutor(2) as pool:list(pool.map(lambda f:retrieve(a.directory,f),FILES.items()))
    with tarfile.open(a.directory/"engine.tar.gz") as archive:
        archive.extractall(a.directory/"engine",filter="data")
    engine=a.directory/"engine"/"llama-b8058"/"llama-server"
    with engine.open("rb") as f:
        if hashlib.file_digest(f,"sha256").hexdigest()!="36a0e300a5f827798fc4ad253ab35e6ceea2b82e4e060ef9fd73397fcf083b50":
            raise ValueError("executable digest mismatch")
    print(json.dumps({"engine":str(engine),"model":str(a.directory/"model.gguf"),"model_id":MODEL_ID},indent=2))
