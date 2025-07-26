# Fayl nomlari
input_file = "rockyou.txt"
output_file = "rockyou1.txt"

# Natijani yozish
with open(input_file, "r", encoding="latin-1") as infile, open(output_file, "w", encoding="utf-8") as outfile:
    count = 0
    for line in infile:
        password = line.strip()
        if len(password) >= 8:
            outfile.write(password + "\n")
            count += 1

print(f"{count} ta parol '{output_file}' faylga yozildi.")
