#
# Copyright 2017, Intel Corporation
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

find_program(PANDOC pandoc)
if (NOT PANDOC)
        message(WARNING "pandoc not found")
endif()

add_custom_target(manpages)

function(generate_manpage name)
        add_custom_target(manpage-${name}
                          COMMAND ${CMAKE_SOURCE_DIR}/utils/md2man.sh
                                  ${CMAKE_CURRENT_SOURCE_DIR}/${name}.md
                                  ${CMAKE_CURRENT_SOURCE_DIR}/default.man
                                  ${CMAKE_CURRENT_SOURCE_DIR}/generated/${name})
        add_dependencies(manpages manpage-${name})
endfunction()

generate_manpage(libsyscall_intercept.3)

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/generated/libsyscall_intercept.3
       DESTINATION ${CMAKE_INSTALL_MANDIR}/man3 CONFIGURATIONS Release None)
