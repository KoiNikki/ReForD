# 定义输入文件列表和输出文件的路径  
input_files = ['data/cve-2019-9193/cve-2019-9193-attack-1.log']  # 多个原始文件路径  
output_file_path = 'test/output.txt'  # 新文件路径  

# 打开新文件进行写入  
with open(output_file_path, 'w') as output_file:  
    # 遍历输入文件列表  
    for input_file_path in input_files:  
        # 打开每个原始文件进行读取  
        with open(input_file_path, 'r') as input_file:  
            # 遍历原始文件的每一行  
            for line in input_file:  
                # 检查当前行是否包含 'open'  
                if '< open ' in line:  
                    # 如果包含，则写入新文件  
                    output_file.write(line)  

print(f"所有包含 'open' 的行已写入 {output_file_path}")