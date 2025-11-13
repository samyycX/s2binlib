
from multiprocessing import process
import subprocess
import platform
import shutil
import os
from dotenv import load_dotenv


def download_depot(depot_id):
    executable = './data/DepotDownloader.exe'

    args = ['-app', '730', '-depot', str(depot_id), '-dir', f"./binaries", '-filelist', './data/files.txt']

    command = [executable] + args
    print(f"Running command for depot {depot_id}: {' '.join(command)}")

    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    stdout, stderr = process.communicate()

    print(f"Output from Depot {depot_id}:")
    print(stdout.decode())

    if stderr:
        print(f"Error from Depot {depot_id}:")
        print(stderr.decode())

def download_depots():
  download_depot(2347771)
  download_depot(2347773)

def dump():
  executable = "../target/release/s2binlib_dumper.exe"

  args = [executable, "-l", "./binaries/game", "-w", "./binaries/game", "-o", "../dump"]

  process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

  stdout, stderr = process.communicate()

  print(stdout.decode())
  print(stderr.decode())

def cleanup():
  if os.path.exists("./binaries"):
    shutil.rmtree("./binaries")

def main():
  try:
    download_depots()
    dump()
  finally:
    cleanup()

if __name__ == "__main__":
  main()