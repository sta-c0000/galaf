/*
Description: execute command under allow-list application firewall group

gcc galaf-test.c -o galaf-test # build with gcc or clang
install -p galaf-test /usr/local/bin/galaf # (as root)
setcap cap_setgid+ep /usr/local/bin/galaf # (as root) give cap_setgid superpowers

*/

#include <grp.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define GID_RANGE_START 30000
#define GID_RANGE_END   59999

int main( int argc, char *argv[] ) {

    struct group *gr;
    int rc;

    if( argc < 3 ) {
        printf( "Usage: galaf group command [argument ...]\n" );
        return EXIT_FAILURE;
    }

    if( !(gr = getgrnam( argv[1] )) ) {
        printf( "ERROR: group %s does not exist\n", argv[1] );
        return EXIT_FAILURE;
    }

    if( gr->gr_gid < GID_RANGE_START || gr->gr_gid > GID_RANGE_END ) {
        printf( "ERROR: group %s is outside allowable gid range\n", argv[1] );
        return EXIT_FAILURE;
    }

    // set new real and effective gid
    if( setregid( gr->gr_gid, gr->gr_gid ) ) {
        perror( "Unable to change group" );
        return EXIT_FAILURE;
    }

    // TODO: add restrictions... (see minimal galaf.c example)
    // XXX: execvp is for simplified example/testing! execs anything in PATH...
    rc = execvp( argv[2], &argv[2] );
    if( rc ) {
        perror(argv[2]);
        return rc;
    }
}
