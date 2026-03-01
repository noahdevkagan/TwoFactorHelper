#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <mach-o/dyld.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    char path[4096];
    uint32_t size = sizeof(path);
    _NSGetExecutablePath(path, &size);

    char *dir = dirname(path);  /* .app/Contents/MacOS */
    char setup[4096];
    char script[4096];
    snprintf(setup, sizeof(setup), "%s/../Resources/setup.sh", dir);
    snprintf(script, sizeof(script), "%s/../Resources/twofactor.py", dir);

    /* Run setup first (installs PyObjC if needed) */
    char setup_cmd[4200];
    snprintf(setup_cmd, sizeof(setup_cmd), "/bin/bash \"%s\"", setup);
    system(setup_cmd);

    /* Try python3 paths in order of preference */
    const char *pythons[] = {
        "/usr/bin/python3",
        "/usr/local/bin/python3",
        "/opt/homebrew/bin/python3",
        "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/Current/bin/python3",
        "/Library/Developer/CommandLineTools/usr/bin/python3",
        NULL
    };

    for (int i = 0; pythons[i] != NULL; i++) {
        if (access(pythons[i], X_OK) == 0) {
            execl(pythons[i], "python3", script, NULL);
        }
    }

    /* Last resort: use PATH */
    execlp("python3", "python3", script, NULL);
    return 1;
}
