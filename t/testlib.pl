use 5.010;
use strict;
use warnings;

use File::chdir;
use File::Slurp;
use File::Temp qw(tempdir);
use Passwd::Unix::Alt;
use Test::More 0.96;

my $tmp_dir;

sub setup {
    my ($pua_extra_args) = @_;
    $pua_extra_args //= {};

    $tmp_dir = tempdir(CLEANUP=>1);
    $CWD = $tmp_dir;
    diag "tmp dir is $tmp_dir";

    write_file("$tmp_dir/passwd", <<'_');
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/bin/sh
daemon:x:2:2:daemon:/sbin:/bin/sh
u1:x:1000:1000::/home/u1:/bin/bash
u2:x:1001:1001::/home/u2:/bin/bash
_

    write_file("$tmp_dir/shadow", <<'_');
root:*:14607:0:99999:7:::
bin:*:14607:0:99999:7:::
daemon:*:14607:0:99999:7:::
u1:*:14607:0:99999:7:::
u2:*:14607:0:99999:7:::
_

    write_file("$tmp_dir/group", <<'_');
root:x:0:
bin:x:1:
daemon:x:2:
nobody:x:111:
u1:x:1000:u1
u2:x:1001:u2
_

    write_file("$tmp_dir/gshadow", <<'_');
root:::
bin:::
daemon:::
nobody:!::
u1:!::
u2:!::u1
_
    $::pu //= Passwd::Unix::Alt->new(
        passwd  => "$tmp_dir/passwd",
        group   => "$tmp_dir/group",
        shadow  => "$tmp_dir/shadow",
        gshadow => "$tmp_dir/gshadow",
	%$pua_extra_args,
    );
}

sub teardown {
    done_testing();
    if (Test::More->builder->is_passing) {
        #diag "all tests successful, deleting tmp dir";
        $CWD = "/";
    } else {
        diag "there are failing tests, not deleting tmp dir";
    }
}

1;
