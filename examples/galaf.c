/*
    galaf = group allow-list application firewall
    Description: execute binary under allowlist application firewall group
    Copyright (C) 2022 Alain Ducharme

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

#   Prerequisites: (other than basic, e.g. build-essential)
apt install libjson-glib-dev # GLib JSON library development files
#   Build with gcc or clang:
gcc galaf.c $(pkg-config --cflags --libs json-glib-1.0) -o galaf
#   Install (as root):
install -p galaf /usr/local/bin/
#   Grant galaf cap_setgid superpowers (as root):
setcap cap_setgid+ep /usr/local/bin/galaf

*/

#include <grp.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <json-glib/json-glib.h>

#define GALAF_JSON "/usr/local/etc/galaf/galaf.json"

int main( int argc, char *argv[] ) {

    struct group *gr;
    JsonParser *parser;
    GError *error = NULL;
    JsonReader *reader;
    unsigned int gid_min = 0, gid_max = 0;
    int i, j, count, rc, newargc = 0;
    int ok = 1, ellipsis = 0;
    const char* str;
    char** newargv = NULL;

    if( argc < 2 ) {
        printf( "Usage: galaf group [argument ...]\n" );
        return EXIT_FAILURE;
    }

    if( !(gr = getgrnam( argv[1] )) ) {
        printf( "ERROR: group %s does not exist\n", argv[1] );
        return EXIT_FAILURE;
    }

    parser = json_parser_new();

    json_parser_load_from_file( parser, GALAF_JSON, &error );
    if( error ) {
        printf( "Cannot parse `%s': %s\n", GALAF_JSON, error->message );
        g_error_free( error );
        g_object_unref( parser );
        return EXIT_FAILURE;
    }

    reader = json_reader_new( json_parser_get_root( parser ) );

    if( json_reader_read_member( reader, "config" ) &&
        json_reader_read_member( reader, "gid_range" ) ) {

        json_reader_read_element( reader, 0 );
        gid_min = json_reader_get_int_value( reader );
        json_reader_end_element( reader );
        json_reader_read_element( reader, 1 );
        gid_max = json_reader_get_int_value( reader );
        json_reader_end_element( reader );
        json_reader_end_member( reader ); // gid_range
        json_reader_end_member( reader ); // config
    }
    else
        ok = 0;

    // printf( "gid_range = %d to %d\n", gid_min, gid_max );
    if( !gid_min || !gid_max ) {
        printf( "ERROR: %s does not have valid config: gid_range\n", GALAF_JSON );
        ok = 0;
    }

    if( ok && ( gr->gr_gid < gid_min || gr->gr_gid > gid_max ) ) {
        printf( "ERROR: group %s is outside allowable gid range\n", argv[1] );
        ok = 0;
    }

    if( ok &&
        json_reader_read_member( reader, "groups" ) &&
        json_reader_read_member( reader, argv[1] ) &&
        json_reader_read_member( reader, "execv" ) ) {

        // considered: wordexp( cmdline, &we, WRDE_NOCMD )

        count = json_reader_count_elements( reader );

        newargv = malloc( sizeof( char* ) * ( count + argc + 1 ) );
        if( !newargv ) {
            perror( "Cannot allocate newargv" );
            g_object_unref( reader );
            g_object_unref( parser );
            return EXIT_FAILURE;
        }

        for( i = 0; i < count; i++ ) {
            json_reader_read_element( reader, i );
            str = json_reader_get_string_value( reader );
            if( strcmp( str, "…" ) == 0 ) {
                if( !ellipsis++ ) { // only allow once (newargv malloc)
                    for( j = 2; j < argc; j++ ) {
                        newargv[newargc++] = argv[j]; // pointers
                    }
                }
            }
            else {
                newargv[newargc++] = strdup( str );
            }
            json_reader_end_element( reader );
        }
        newargv[newargc] = NULL; // end of array

        /*
        printf( "command line: " );
        for( i = 0; i < newargc; i++ ) {
            printf( i ? ", '%s'" : "'%s'", newargv[i] );
        }
        printf( "\n" );
        */
    }

    g_object_unref( reader );
    g_object_unref( parser );

    if( !ok ) {
        return EXIT_FAILURE;
    }

    if( !newargv || !newargv[0] || !newargv[0][0] ) {
        printf( "ERROR: no execv defined for group %s\n", argv[1] );
        return EXIT_FAILURE;
    }

    // set new real and effective gid
    if( setregid( gr->gr_gid, gr->gr_gid ) ) {
        perror( "Unable to change group" );
        return EXIT_FAILURE;
    }

    rc = execv( newargv[0], &newargv[0] );
    // never get past here unless error
    if( rc ) {
        perror( newargv[0] );
        return rc;
    }
}
