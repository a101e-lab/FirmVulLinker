import subprocess
import os
import ssdeep
from OpenSSL import crypto
from Crypto.PublicKey import RSA
import hashlib
def extract_bin_file(firmware_extracted_path,filesystem_path):
    # filesystem_path,filesystem_relpath = find_squashfs_root(firmware_extracted_path)
    # if filesystem_path:
    bin_list=[]
    bin_path_list=[]
    for root, dirs, files in os.walk(filesystem_path):
        for file in files:
            file_dic={}
            hash_list = []
            file_path = os.path.join(root, file)
            output = subprocess.check_output(["file", "-b",file_path]).decode("utf-8").lower()
            # 检查输出中是否包含"executable"、"shared object"或"Mach-O"
            binary_keywords = [
        "executable", "shared object", "mach-o", "archive", "dll", "data", "image", "compressed"
    ]
            if any(keyword in output for keyword in binary_keywords):
                if os.path.isfile(file_path) and not os.path.islink(file_path):
                    bin_path_list.append(file_path)
                    print(f"{file_path}: File is a binary file")
                    file_relpath=os.path.relpath(file_path, filesystem_path)
                    hash_list.append(calculate_file_hash(file_path))
                    hash_list.append(calculate_sdhash(file_path))
                    hash_list.append(calculate_ssdeep_hash(file_path))
                    file_dic[file_relpath]=hash_list
                    bin_list.append(file_dic)
            else:
                print(f"{file_path}: File is not a binary file")
    return bin_list,bin_path_list
    
def extract_ca_file(ssl_related_file,ca_list):
    if ".key" in str(ssl_related_file):
        pass
    else:
        ca_list.append(ssl_related_file)
    return ca_list

def extract_directory(filesystem_path):
    # filesystem_path,filesystem_relpath = find_squashfs_root(firmware_extracted_path)
    # if filesystem_relpath:
    #     directory_structure = {}
    #     for root, dirs, files in os.walk(filesystem_relpath):
    #         folders = root.split(os.sep)
    #         current_level = directory_structure
    #         for folder in folders[1:]:
    #             current_level = current_level.setdefault(folder, {})
            
    #         for f in files:
    #             current_level[f] = None
        
    # return directory_structure
    """
    获取目录下所有文件的路径，并返回一个集合。
    """
    file_paths = set()
    for dirpath, dirnames, filenames in os.walk(filesystem_path):
        for filename in filenames:
            file_path = os.path.relpath(os.path.join(dirpath, filename), filesystem_path)
            file_paths.add(file_path)
    return file_paths



def extract_configuration_file(firmware_extracted_path):
    filesystem_path,filesystem_relpath = find_squashfs_root(firmware_extracted_path)
    if filesystem_path:
    # 查找所有 .conf, .cfg, .ini 文件
        result = subprocess.run(["find", filesystem_path, "-type", "f", "-name", "*.conf", "-o", "-name", "*.cfg", "-o", "-name", "*.ini"], capture_output=True, text=True)
        if result.stdout:
            file_list = result.stdout.split('\n')
            file_list = file_list[:-1]
            configuration_list = [file.replace(filesystem_path, '') for file in file_list]
            return configuration_list
        else:
            return None
    else:
        print("未找到名为'squashfs-root'的文件夹")
        return None


def find_squashfs_root(firmware_extracted_path):
    """
    找到文件系统的路径，还需添加其他文件系统的名字
    """
    for root, directories, files in os.walk(firmware_extracted_path):
        if os.path.basename(root) == "squashfs-root":
            if os.path.exists(os.path.abspath(root)):
                return os.path.abspath(root),os.path.relpath(root)
            else:
                return None,None
        # elif "squashfs-root" in directories:
        #     # print(os.path.join(root, "squashfs-root"))
        #     if os.path.exists(os.path.join(root, "squashfs-root")):
        #         return os.path.join(root, "squashfs-root")
        #     else:
        #         return None
    return None

def calculate_sdhash(filepath):
    """
    输出示例：
    sdbf:03:36:/root/firmware_analysis_tool/main.py:14768:sha1:256:5:7ff:160:2:92:iiUUUxCuwALClgG0YgBoIxp5HpZQBUe2AZVKXEAC5BhorBAQF4NNAoFFRBjxC5gZDPjQAYQuhP0AotlZBBDWiBGCAPlGAAICJ0wAkCxBVYR9gRBQJrkAZegYRhAYsA7HIBQwSRbDlUgBAwACKkAAS9oBHoOoEEIOQAECAaktBGOiQHE9FAQrLxF67YRCAQxATU1ACWYRQFCzhYZrFyIKSDFC3xGETAEYKBBtVsTn6DgaUCoFiKoEfmMDSNglFAPBUKEfk4EMLRUAL5QAngUwZNEwoAAaBAAiDmEVEAAIHYH6BoDAIAwoEiEN4sAEIJHNEIYqICSgEuORImhoAQAhjAIARgAABMASIAAhKABSAAAAUSQECCDkAISg4gUIJApFgLIiBIhMAYBEAAIEOiYKIAwEVAAgAAEEEAmKCjhggIIEdYICYAQE3CpQIpAGACEAQBBQCkAsoEAADA4ikQBAiEEAA4CgA0ARQAAICAACWAhKMEAL2AyAAAYAAgCEQSQACYAXYMDCAAIIAIBEQiRogJCgkEABYAAygAMQAIAQ8AABQEEABRiCgBBBADUggABAXAWAKiWiFRwKEAQgEAAkgUAaiAFAAAJCoAgAJCQgkQAAGEAAhAAGAEEAAEBRAYQGgCYPmCYAggIkEAQEgAAiNQcjIEQCwApCQo0QCAQgBEA=
    """
    try:
        # 调用sdhash命令行工具
        result = subprocess.run(["sdhash", filepath], capture_output=True, text=True, check=True)
        # 输出是标准输出，包含哈希值
        hash_value = extract_hash(result.stdout)
        return hash_value
    except subprocess.CalledProcessError as e:
        # 如果命令运行失败（例如文件不存在或sdhash未安装）
        return e.stderr
    except Exception as e:
        # 其他错误
        return str(e)

def extract_hash(output):
    start_index = output.find("sha1:")  # 找到哈希值起始位置
    if start_index != -1:
        return output[start_index+5:]  # 提取哈希值
    else:
        return "Hash value not found"  # 如果未找到哈希值，则返回错误消息

def calculate_ssdeep_hash(filepath):
    """
    输出示例：
    384:CcN2AlTAfPn0oMTOOQ3SKAMFM9ToTN6iNu4AjAr5A7M:CC2AlTAfPncTOOQ3SKASQT8MiNu4AjAl
    """
    try:
        with open(filepath, "rb") as file:
            data = file.read()
            return ssdeep.hash(data)
    except FileNotFoundError:
        return "File not found."
    except Exception as e:
        return str(e)

def extract_public_private_key(private_key_file):
    if os.path.splitext(private_key_file)[1].lower() == ".pem" or os.path.splitext(private_key_file)[1].lower() == ".key":
        #待补充类型
        with open(private_key_file, 'r') as file:
            file_content=file.read()
        if "Subject Public Key Info" in file_content or "Modulus" in file_content:
            result=extract_modulus_exponent_from_crt(file_content)
            if isinstance(result, tuple):
                modulus, exponent = result
                public_key_output=generate_public_key_from_crt(modulus, exponent)
                return None,public_key_output.decode('utf-8')
            elif isinstance(result, str):
                print("Error:", result)
                return None, None
        elif "BEGIN CERTIFICATE" in file_content:   
            return None, None
        else:
                private_key_output,public_key_output=generate_public_key_from_private_key(private_key_file)
                if private_key_output and public_key_output:
                    return private_key_output,public_key_output
                else:
                    return None, None
    #crt文件：
    #首先解析crt内容，解析结果为标准证书内容
    elif os.path.splitext(private_key_file)[1].lower() == ".crt":
        openssl_output=parse_ca_from_crt(private_key_file)
        result=extract_modulus_exponent_from_crt(openssl_output)
        if isinstance(result, tuple):
            modulus, exponent = result
            public_key_output=generate_public_key_from_crt(modulus, exponent)
            return None,public_key_output.decode('utf-8')
        elif isinstance(result, str):
            print("Error:", result)
            return None, None


def parse_ca_from_crt(crt_file):
    """
    需要在更多案例下补充，如果不是一段编码，会是什么样的？目前认为是证书内容本身
    """
    with open(crt_file, 'r') as file:
        if "BEGIN CERTIFICATE" in file.read():
            # 使用openssl x509命令解析crt文件
            openssl_output = subprocess.check_output(['openssl', 'x509', '-noout', '-text', '-in', crt_file])
            return openssl_output.decode('utf-8')
        else:
            return file.read()

def extract_modulus_exponent_from_crt(openssl_output):
    # 检查公钥算法是否为rsaEncryption    
    if 'rsaEncryption' not in openssl_output:
        return "Not an RSA Public Key"

    # 初始化模数和指数
    modulus = ''
    exponent = ''

    # 提取模数和指数
    try:
        modulus_start = openssl_output.index('Modulus') + len('Modulus')
        modulus_end = openssl_output.index('Exponent:')
        modulus = openssl_output[modulus_start:modulus_end].strip().replace('\n', '').replace('    ', '')
        exponent = openssl_output[modulus_end:].split(':')[1].strip().split(' ')[0]
    except ValueError:
        return "Failed to extract modulus and exponent"

    return modulus, exponent

def generate_public_key_from_crt(modulus, exponent):
    modulus = modulus.replace(" ","").replace(":","").replace("\n","").replace("(","").replace(")","").replace("2048","").replace("bit","")
    modulus = int(modulus,16)
    # 创建RSA公钥对象
    public_key = RSA.construct((modulus, int(exponent)))
    return public_key.exportKey()

def generate_public_key_from_private_key(private_key_file):
    try:
        # 从私钥文件中提取私钥，添加 -passin pass: 参数自动提供空密码
        command = f"openssl rsa -in {private_key_file} -passin pass: -batch"
        private_key_output = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.DEVNULL)
        
        # 从私钥文件中提取公钥，添加 -passin pass: 参数自动提供空密码
        command = f"openssl rsa -in {private_key_file} -pubout -passin pass: -batch"
        public_key_output = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.DEVNULL)

        return private_key_output, public_key_output
    except subprocess.CalledProcessError as e:
        print(f"无法提取密钥（可能是加密的或需要密码）: {private_key_file}")
        return None, None
    
def calculate_file_hash(file_path, hash_algorithm='sha256'):
    """
    计算输入文件的哈希值。

    :param file_path: 文件路径
    :param hash_algorithm: 哈希算法，默认使用 'sha256'
    :return: 文件的哈希值
    """
    hash_func = hashlib.new(hash_algorithm)
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None
    except Exception as e:
        print(f"Error occurred: {e}")
        return None

# extract_bin_file("/root/firmware_analysis_tool/processed/_DAP-1665_REVB_FIRMWARE_PATCH_v2.02B01_BETA.zip.extracted")
# r=extract_configuration_file("/root/firmware_analysis_tool/processed/_tenda_ac9.zip.extracted/squashfs-root")
# print(r)
# generate_public_key_from_private_key("/root/firmware_analysis_tool/processed/_DAP-1665_REVB_FIRMWARE_PATCH_v2.02B01_BETA.zip.extracted/_DAP1665_FW202beta01_hboe.bin.extracted/squashfs-root/etc/stunnel.key")
# print(extracted_private_key.decode())
# crt_file = "/home/firmware_analysis_tool/binwalk_docker_result/extract_result/_tenda_ac9.zip.extracted/squashfs-root/webroot_ro/pem/certSrv.crt"
# openssl_output=parse_ca_from_crt(crt_file)
# print(openssl_output)
# modulus, exponent=extract_modulus_exponent_from_crt(openssl_output)
# print(type(modulus), exponent)
# public_key=generate_public_key_from_crt(modulus, exponent)
# print(public_key)
# a,b=extract_public_private_key("/root/firmware_analysis_tool/processed/_DAP-1665_REVB_FIRMWARE_PATCH_v2.02B01_BETA.zip.extracted/_DAP1665_FW202beta01_hboe.bin.extracted/squashfs-root/etc/stunnel_cert.pem")
# print(a,b)