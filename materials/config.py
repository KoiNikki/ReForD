import re


SYSCALL_PROC_START = ["fork", "vfork", "clone"]
REGEX_PROC_START = re.compile(
    r".*exe=(?P<exe>.*)(?: args.*)?pid=(?P<pid>\d*)\(.* ptid=(?P<ppid>\d*)\((?P<ppname>.*)\)(?: cwd=.*)?flags=(?P<flags>.*) uid=(?P<uid>\d*) gid=(?P<gid>\d*).*",
    re.DOTALL,
)

SYSCALL_PROC_END_ACTIVE = ["procexit"]
REGEX_PROC_END_ACTIVE = re.compile(
    r"status=(?P<status>\d*) ret=(?P<ret>\d*).*", re.DOTALL
)

SYSCALL_FILE_EXEC = ["execve"]
REGEX_FILE_EXEC = re.compile(
    r"res=(?P<res>.*) exe=(?P<exe>.*)(?: args.*)?pid=(?P<pid>\d*)\(.* ptid=(?P<ppid>\d*)\((?P<ppname>.*)\)(?: cwd=.*)?flags=(?P<flags>.*).*",
    re.DOTALL,
)

SYSCALL_FILE_OPEN = ["open", "openat", "openat2"]
REGEX_FILE_OPEN = re.compile(
    r"fd=(?P<fd_num>[-\d]*)\(?(<(?P<fd_type>\w{1,2})>)?((?P<fd_content>.*)\))? dirfd=.*flags=(?P<flags>.*) mode=.*",
    re.DOTALL,
)
REGEX_DIR_OPEN = re.compile(
    r"dirfd=(?P<fd_num>.*) name=(?P<fd_content>.*) flags=(?P<flags>.*) mode=.*",
    re.DOTALL,
)

SYSCALL_FILE_CREAT = ["creat"]
REGEX_FILE_CREAT = re.compile(
    r"fd=(?P<fd_num>[-\d]*)\(?(<(?P<fd_type>\w{1,2})>)?((?P<fd_content>[^()]*)\))?.*mode=.*",
    re.DOTALL,
)

SYSCALL_FILE_DEL = ["unlink", "unlinkat"]
REGEX_FILE_DEL_UNLINK = re.compile(r"res=(?P<res>\d*) path=(?P<path>.*)", re.DOTALL)
REGEX_FILE_DEL_UNLINKAT = re.compile(
    r"res=(?P<res>\d*).*name=(?P<name>.*) flags=.*", re.DOTALL
)

SYSCALL_FILE_WRITE = [
    "write",
    "pwrite",
    "writev",
    "pwritev",
    "send",
    "sendto",
    "sendmsg",
]
REGEX_FILE_WRITE_ARGS = re.compile(
    r"fd=(?P<fd_num>[-\d]*)\(?(<(?P<fd_type>\w{1,2})>)?((?P<fd_content>.*)\))? size=.*",
    re.DOTALL,
)
REGEX_FILE_WRITE_ARGS_BAK = re.compile(
    r"fd=(?P<fd_num>[-\d]*)\(?(<(?P<fd_type>\w{1,2})>)?((?P<fd_content>.*)\))?.*",
    re.DOTALL,
)
REGEX_FILE_WRITE_RES = re.compile(r"res=(?P<res>\d*).*", re.DOTALL)

SYSCALL_FILE_READ = [
    "read",
    "pread",
    "readv",
    "preadv",
    "recv",
    "recvfrom",
    "recvmsg",
]
REGEX_FILE_READ_ARGS = re.compile(
    r"fd=(?P<fd_num>[-\d]*)\(?(<(?P<fd_type>\w{1,2})>)?((?P<fd_content>.*)\))? size=.*",
    re.DOTALL,
)
REGEX_FILE_READ_ARGS_BAK = re.compile(
    r"fd=(?P<fd_num>[-\d]*)\(?(<(?P<fd_type>\w{1,2})>)?((?P<fd_content>.*)\))?.*",
    re.DOTALL,
)
REGEX_FILE_READ_RES = re.compile(r"res=(?P<res>\d*).*", re.DOTALL)
