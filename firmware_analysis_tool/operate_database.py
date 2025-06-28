from mysql_database import Database
from mysql.connector import Error, errorcode
from config_loader import load_config

# 加载配置
config = load_config()
db_config = config["database"]

db = Database(
    db_config["host"], 
    db_config["user"], 
    db_config["password"], 
    db_config["db_name"], 
    port=db_config["port"]
)

def get_or_create_firmware_id(hash_value, firmware_name, architecture, filesystem, operating_system):
    """
    获取或创建 firmware_info 表中的 firmware_id。
    """
    select_query = f"""
    SELECT id FROM firmware_info WHERE firmware_hash = '{hash_value}' AND firmware_name = '{firmware_name}';
    """
    result = db.execute_read_query(select_query)
    if result:
        return result[0][0]
    else:
        # 插入新的 firmware_info 记录
        insert_firmware_info_query = f"""
        INSERT INTO firmware_info (firmware_hash, firmware_name, architecture, filesystem, operating_system)
        VALUES ('{hash_value}', '{firmware_name}', '{architecture}', '{filesystem}', '{operating_system}');
        """
        db.execute_query(insert_firmware_info_query)
        return db.execute_read_query(select_query)[0][0]

def store_firmware_info(hash_value, firmware_name, architecture, filesystem, operating_system):
    """
    存储 firmware_info 信息。
    """
    firmware_id = get_or_create_firmware_id(hash_value, firmware_name, architecture, filesystem, operating_system)
    return firmware_id
def store_fuzzy_hashes(firmware_id, bin_list):
    """
    存储模糊哈希记录。
    """
    # 插入 fuzzy_hashes 记录
    for it in bin_list:
        for file_name, hashes in it.items():
            file_hash = hashes[0] if hashes[0] else None
            sdhash_hash = hashes[1] if hashes[0] != "Hash value not found" else None
            ssdeep_hash = hashes[2] if len(hashes) > 2 else None

            # 检查是否已经存在相同的记录
            select_query = f"""
            SELECT id FROM fuzzy_hashes WHERE firmware_id = '{firmware_id}' AND file_hash = '{file_hash}';
            """
            result = db.execute_read_query(select_query)
            if not result:
                insert_query = f"""
                INSERT INTO fuzzy_hashes (firmware_id, file_name, file_hash, ssdeep_hash, sdhash_hash)
                VALUES ('{firmware_id}', '{file_name}', '{file_hash}', '{ssdeep_hash}', '{sdhash_hash}');
                """
                try:
                    db.execute_query(insert_query)
                    print(f"Successfully inserted: {file_name}")
                except Error as e:
                    if e.errno == errorcode.ER_DUP_ENTRY:
                        print(f"Duplicate entry for file: {file_name}")
                    else:
                        print(f"Error occurred: {e}")

def find_file_by_hash(file_hash):
    """
    根据 file_hash 查找数据库中匹配的记录，并返回命中的 file_name。

    :param file_hash: 文件的哈希值
    :return: 命中的 file_name 列表
    """
    select_query = f"""
    SELECT file_name FROM fuzzy_hashes WHERE file_hash = '{file_hash}';
    """
    try:
        result = db.execute_read_query(select_query)
        if result:
            return [row[0] for row in result]
        else:
            return []
    except Error as e:
        print(f"Error occurred: {e}")
        return []

def get_all_ssdeep_hashes(db):
    """
    返回数据库中所有的 ssdeep_hash 及其对应的 file_name、firmware_name 和 firmware_hash。

    :return: 包含 ssdeep_hash、file_name、firmware_name 和 firmware_hash 的列表
    """
    select_query = """
    SELECT fh.ssdeep_hash, fh.file_name, fi.firmware_name, fi.firmware_hash
    FROM fuzzy_hashes fh
    JOIN firmware_info fi ON fh.firmware_id = fi.id;
    """
    try:
        result = db.execute_read_query(select_query)
        if result:
            return [(row[0], row[1], row[2], row[3]) for row in result]
        else:
            return []
    except Error as e:
        print(f"Error occurred: {e}")
        return []