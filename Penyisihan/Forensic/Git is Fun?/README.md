## Judul Soal
Git is Fun?

## Deskripsi Soal
> In a certain place, there's an old thing. At first, there's nothing special about it. But, if you look deep enough, you'll eventually find a time machine brings you back to a certain moment.

## Hint Soal
- RFC 1813

---

## Penjelasan Penyelesaian Soal

Diberikan berkas `history.tar.gz` yang memuat *network packet* `history.pcap`. Sebagaimana *network packet* lainnya, terlebih dahulu kita lakukan enumerasi informasi terkait hierarchy paket

<br>

**Packet Enumeration**

```bash
❯ tshark -r history.pcap -q -z io,phs                                                                                             

===================================================================
Protocol Hierarchy Statistics
Filter: 

eth                                      frames:4260 bytes:720432
  ip                                     frames:4260 bytes:720432
    udp                                  frames:4249 bytes:703778
      rpc                                frames:4238 bytes:702260
        nfs                              frames:4238 bytes:702260
      data                               frames:11 bytes:1518
    data                                 frames:11 bytes:16654
===================================================================

```

```
❯ tshark -r history.pcap | head                                                                                                   
    1   0.000000 192.168.0.110 → 192.168.0.101 NFS 206 V2 GETATTR Call, FH: 0x4e20edbb
    2   0.000105 192.168.0.101 → 192.168.0.110 NFS 138 V2 GETATTR Reply (Call In 1)
    3   0.002810 192.168.0.110 → 192.168.0.101 NFS 222 V2 LOOKUP Call, DH: 0x4e20edbb/commondir
    4   0.002917 192.168.0.101 → 192.168.0.110 NFS 70 V2 LOOKUP Reply (Call In 3) Error: NFS2ERR_NOENT
    5   0.006788 192.168.0.110 → 192.168.0.101 NFS 206 V2 GETATTR Call, FH: 0x4e20edbb
    6   0.006880 192.168.0.101 → 192.168.0.110 NFS 138 V2 GETATTR Reply (Call In 5)
    7   0.009662 192.168.0.110 → 192.168.0.101 NFS 218 V2 LOOKUP Call, DH: 0x4e20edbb/config
    8   0.009755 192.168.0.101 → 192.168.0.110 NFS 70 V2 LOOKUP Reply (Call In 7) Error: NFS2ERR_NOENT
    9   0.011336 192.168.0.110 → 192.168.0.101 NFS 218 V2 LOOKUP Call, DH: 0x4e20edbb/config
   10   0.011401 192.168.0.101 → 192.168.0.110 NFS 70 V2 LOOKUP Reply (Call In 9) Error: NFS2ERR_NOENT

```

Hasilnya, kita menjumpai sekumpulan UDP packet dengan spesifikasi `NFS-v2`. Setelah beberapa saat melakukan observasi, diketahui pula bahwa terjadi `data transfer` antara `client-server` yang melibatkan berkas `Github Repository`.

<br>

**Directory & File reconstruction**

Berdasarkan pemahaman sebelumnya, disini kita akan melakukan skema rekonstruksi `directory` beserta `file` Github Repository sesuai dengan spesifikasi yang tertera pada dokumentasi [NFS](https://tools.ietf.org/html/rfc1813).

Berikut merupakan `brief history`yang dihasilkan dari eksekusi `nfs-parser.py`

```bash
❯ python2 nfs-parser.py history.pcap | head                                                                                       
V2 GETATTR Call, FH: 0x4e20edbb V2 GETATTR Reply (Call In 1)
V2 CREATE Call, DH: 0x4e20edbb/description V2 CREATE Reply (Call In 3), FH: 0xa492319b
[~] Creating File git/description
V2 WRITE Call, FH: 0xa492319b BeginOffset: 0 Offset: 0 TotalCount: 73 V2 WRITE Reply (Call In 5)
[v] Writing git/description
V2 MKDIR Call, DH: 0x4e20edbb/branches V2 MKDIR Reply (Call In 7), FH: 0x94915f70
[+] Creating branches directory
V2 MKDIR Call, DH: 0x4e20edbb/hooks V2 MKDIR Reply (Call In 9), FH: 0xff93101e
[+] Creating hooks directory
V2 CREATE Call, DH: 0xff93101e/pre-applypatch.sample V2 CREATE Reply (Call In 11), FH: 0x95d361d8

```

Adapun berikut adalah Github Repository hasil rekonstruksi:

```bash
❯ tree git -L 1                                                                                                                   
git
├── branches
├── config
├── config.lock
├── description
├── HEAD
├── HEAD.lock
├── hooks
├── info
├── objects
└── refs
```

Berdasarkan informasi yang telah diperoleh sebelumnya, kita dapat menyimpulkan bahwa repository yang diperoleh ada `Bare Repository` dari sebuah Git Server.

Dari sini, kita perlu mengubahnya menjadi `Normal repository` untuk dapat mengakses VCS management sebagainya Github Repository pada umumnya.

```bash
❯ mkdir normal-repo                                              
❯ mv git normal-repo/.git                                                      ❯ cd normal-repo                                              ❯ rm -rf .git/*.lock                                                     ❯ git config --local --bool core.bare false 

❯ git log --oneline | head 

2d40c42 Clear all character of flag
dcb1ac7 Add 73th character of flag
bbccac7 Remove 73th character of flag
43e736f Add 27th character of flag
ffc57d2 Remove 27th character of flag
5b0e2cc Add 45th character of flag
9759898 Remove 45th character of flag
91799e3 Add 9th character of flag
4cb8bdd Remove 9th character of flag
cdcc68a Add 17th character of flag
```

<br>

**Information Retrieval**

Sesaat setelah mendapatkan akses vcs dari `normal repository`, kita menjumpai berapa `commit` yang berisikan `flag addition/removal` dari berkas `flag.txt` sebanyak 1 karakter.

Untuk memperoleh semua informasi yang dibutuhkan, kita lakukan proses sebagai berikut:

```bash
$ git log --oneline > ../logs

$ for i in $(cat ../logs | awk '{print $1}'); \
 do \
  git checkout $i &>/dev/null; \
  cat flag.txt > ../files/$i; \
done
```

Terakhir, menggunakan script berikut kita lakukan proses pemetaan informasi dari `flag.txt`. Hasilnya diperoleh informasi flag sebagai berikut:

```python
# commit-map.py

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

```

```bash
❯ cd ..
❯ python2 commit-map.py

redmask{n3ver_us3_netw0rk_f1l3_sy5tem_for_vcs_rep0s1tory_m4nagem3nt_6de31dfbd3}
```

<br>

## Flag

redmask{n3ver_us3_netw0rk_f1l3_sy5tem_for_vcs_rep0s1tory_m4nagem3nt_6de31dfbd3}