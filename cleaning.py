import csv


def detect_file_encoding(file):
    try:

        with open("rawdatas.csv", "w", encoding="utf-8", newline="") as f:
            with open(file, "r", encoding="utf-16", errors="replace") as source_file:
                reader = csv.reader(source_file, delimiter=",")
                writer = csv.writer(f, delimiter=",")

                # Read and write the header
                headers = next(reader)
                writer.writerow(headers)
                header_count = len(headers)

                # Write rows with the same length as the header
                for row in reader:
                    if len(row) == header_count:
                        stripped_row = [
                            value.strip() if value else value for value in row
                        ]
                        writer.writerow(stripped_row)
                    else:
                        print(f"Skipping invalid row: {(row)}")

        print(
            "File has been saved as 'rawdatas.csv' with UTF-8 encoding, comma delimiter, and stripped whitespace."
        )

    except FileNotFoundError:
        print(
            f"Error: The file '{file}' was not found. Please check the file path and try again."
        )

    except Exception as e:
        print(f"An error occurred: {e}")


detect_file_encoding("datas.csv")
