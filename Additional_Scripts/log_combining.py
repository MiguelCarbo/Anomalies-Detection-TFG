# Log_Combining.py

# Creator: Miguel Ivars Carbo - University of Zaragoza
# Date: 06/03/2023

# This Script will allow the user to take some rows from a log file, keep a chosen
# fraction of them and shuffle them.

# It is developed in order to complement the main goal of the 'Anomalies-Detection-TFG'
# and in the end, provides a log in which 'BENIGN' and 'MALIGN' rows of the different
# logs are shuffled from all the possible days.

import random

# Set the percentage of 'BENIGN' rows to keep
keep_percent_benign = 0.04
keep_percent_malign = 0.01

# Initialize lists to hold the 'MALIGN' and 'BENIGN' rows
malign_rows = []
benign_rows = []

# Open the log file and read each line
with open('E:\Logs_Zeek\CIC-IDS\labeled_logs.log', 'r') as logfile:
    for line in logfile:
        # Check if the line contains 'MALIGN'
        if 'MALIGN' in line:
            # If it does, add it to the malign_rows list
            malign_rows.append(line)
        else:
            # If it doesn't, add it to the benign_rows list
            benign_rows.append(line)

# Calculate the number of 'BENIGN' rows to keep
num_benign_to_keep = int(len(benign_rows) * keep_percent_benign)
num_malign_to_keep = int(len(malign_rows) * keep_percent_malign)

# Randomly select the 'BENIGN/MALIGN' rows to keep
benign_rows_to_keep = random.sample(benign_rows, num_benign_to_keep)
malign_rows_to_keep = random.sample(malign_rows, num_malign_to_keep)

# Combine the 'MALIGN' and selected 'BENIGN' rows into a single list
combined_rows = malign_rows_to_keep + benign_rows_to_keep

# Shuffle the combined rows
random.shuffle(combined_rows)

# Write the selected and shuffled rows to a new file
with open('E:\Logs_Zeek\CIC-IDS\shuffled_logs.log', 'w') as outfile:
    outfile.writelines(combined_rows)
    
print('Total Malign Rows: ' + str(len(malign_rows)))
print('Malign Rows Kept: ' + str(len(malign_rows_to_keep)))
print('Total Kept Rows: ' + str(len(combined_rows)))
print('Finished Execution')
