import os

def read_file(name):
    with open(name, 'rb') as handle:
        return handle.read().strip('\x00')

logs = read_file('logs').split('\n')[:-1]
result = ['']*100

for log in logs[::-1]:
    commit_id = log.split()[0]
    command = log.split()[1]

    if command == 'Add':
        target_file = os.path.join('files', commit_id)
        content = read_file(target_file)
        index = log.split()[2][:-2]
        result[int(index)] = content

    elif command == 'Remove':
        index = log.split()[2][:-2]
        result[int(index)] = ''

print ''.join(result)