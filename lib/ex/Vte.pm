package Vte;

use strict;
use warnings;
use Glib::Object::Introspection;

sub import {
  Glib::Object::Introspection->setup(basename => 'Vte',
                                     version => '2.91',
                                     package => 'Vte');
}

1;
