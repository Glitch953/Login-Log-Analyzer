from datetime import datetime
# Initialize counters and dictionaries
total_attempts = 0
failed_count = 0
success_count = 0
analysis_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
# Store failed and successful login attempts for each user
failed_logins = {}
successful_logins = {}

# Track users with the highest number of failed attempts
most_suspicious_users = []
max_attempts = 0
failure_rate = 0


# Read and analyze the login log file
with open("login_logs.txt", "r") as file:
    for line in file:

        # Split each line into username and login status
        parts = line.split(",")

        # Skip invalid lines that do not contain two fields
        if len(parts) < 2:
            continue

        # Remove extra spaces from the login status
        parts[1] = parts[1].strip()

        # Accept only SUCCESS or FAILED login statuses
        if parts[1] != "SUCCESS" and parts[1] != "FAILED":
            continue

        # Remove extra spaces from the username
        parts[0] = parts[0].strip()

        # Skip records with an empty username
        if not parts[0]:
            continue

        # Count successful login attempts
        if parts[1] == "SUCCESS":
            success_count += 1

            # Update the successful login count for the user
            if parts[0] in successful_logins:
                successful_logins[parts[0]] += 1
            else:
                successful_logins[parts[0]] = 1

        # Count failed login attempts
        if parts[1] == "FAILED":
            failed_count += 1

            # Update the failed login count for the user
            if parts[0] in failed_logins:
                failed_logins[parts[0]] += 1
            else:
                failed_logins[parts[0]] = 1


# Calculate the total number of login attempts
total_attempts = success_count + failed_count


# Calculate and display the failure rate
if total_attempts > 0:
    failure_rate = (failed_count / total_attempts) * 100
    print(f"Failure Rate: {failure_rate:.2f}%")
elif total_attempts ==0:
    print("No login attempts found.")


# Find users with suspicious failed login activity
for username, attempts in failed_logins.items():

    # Display a warning if a user has 3 or more failed attempts
    if attempts >= 3:
        print(f"WARNING: {username} has {attempts} failed login attempts!")

    # Find the user or users with the highest failed login count
    if attempts > max_attempts:
        most_suspicious_users = []
        most_suspicious_users.append(username)
        max_attempts = attempts

    # Include users who have the same highest number of attempts
    elif attempts == max_attempts:
        most_suspicious_users.append(username)


# Display successful login attempts for each user
for username, attempts in successful_logins.items():
    print(f"{username}: {attempts} successful logins")

# Export Data in Report File
with open("report.txt", 'w') as file:
    file.write(f"The Final Result Report \n Total Attempts: {total_attempts} \n FAILED Count: {failed_count} \n SUCCESS Count: {success_count} \n  Failed Logins:{failed_logins} \n Success Logins: {successful_logins} \n Failure Rate: {failure_rate:.2f}% \n Most suspicious users:{', '.join(most_suspicious_users)} ({max_attempts} failed attempts) \n Analysis Date:{analysis_time}")


# Display the final analysis report
print("\n========== LOGIN ANALYSIS REPORT ==========")

print(
    f"Most suspicious users: "
    f"{', '.join(most_suspicious_users) if most_suspicious_users else 'None'} "
    f"({max_attempts} failed attempts)"
)

print(f"Total Attempts: {total_attempts}")
print(f"FAILED Count: {failed_count}")
print(f"SUCCESS Count: {success_count}")
print(f"Failed Logins: {failed_logins}")
print(f"Success Logins: {successful_logins}")
print(analysis_time)

print("===========================================")
