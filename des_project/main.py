block = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

from utils import permute
from permutations import IP

result = permute(block, IP)
print(result)