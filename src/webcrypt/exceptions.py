############################################################################
# Copyright 2021 Plataux LLC                                               #
#                                                                          #
# Licensed under the Apache License, Version 2.0 (the "License");          #
# you may not use this file except in compliance with the License.         #
# You may obtain a copy of the License at                                  #
#                                                                          #
#    https://www.apache.org/licenses/LICENSE-2.0                           #
#                                                                          #
# Unless required by applicable law or agreed to in writing, software      #
# distributed under the License is distributed on an "AS IS" BASIS,        #
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. #
# See the License for the specific language governing permissions and      #
# limitations under the License.                                           #
############################################################################

class TokenException(Exception):
    pass


class InvalidToken(TokenException):
    pass


class AlgoMismatch(TokenException):
    pass


class InvalidSignature(TokenException):
    pass


class InvalidClaims(TokenException):
    pass


class ExpiredSignature(TokenException):
    pass


class NotYetValid(TokenException):
    pass
