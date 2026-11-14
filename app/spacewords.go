package main

// spaceWords — словарь генератора фразы пространства (spacePhraseNew): ровно 256 разных английских слов [a-z]{3,6}
// (одно слово — один байт crypto/rand). ASCII — чтобы фразу одинаково набирали на любой раскладке и ОС. Ключ
// выводится из текста фразы, поэтому правка словаря старые фразы не ломает; состав словаря закреплён тестом.
var spaceWords = [256]string{
	"ant", "bat", "bear", "bee", "bird", "boar", "bull", "cat", "cow", "crab", "crow", "deer", "dog", "duck", "eagle", "eel",
	"elk", "fish", "fox", "frog", "goat", "goose", "hawk", "horse", "lion", "lynx", "mole", "moose", "mouse", "mule", "newt", "owl",
	"otter", "panda", "pig", "pony", "puma", "rat", "raven", "seal", "shark", "sheep", "slug", "snail", "snake", "swan", "tiger", "toad",
	"trout", "tuna", "wasp", "whale", "wolf", "worm", "yak", "zebra", "apple", "bean", "berry", "bread", "cake", "candy", "carrot", "cheese",
	"cherry", "corn", "cream", "egg", "grape", "honey", "lemon", "mango", "melon", "milk", "nut", "olive", "onion", "peach", "pear", "pepper",
	"plum", "rice", "salt", "soup", "sugar", "tea", "toast", "wheat", "amber", "black", "blue", "brown", "coral", "gold", "green", "grey",
	"ivory", "jade", "lilac", "navy", "pink", "purple", "red", "ruby", "silver", "teal", "violet", "white", "yellow", "cloud", "comet", "dawn",
	"desert", "dune", "dust", "earth", "field", "fire", "flame", "fog", "forest", "frost", "glade", "hill", "ice", "island", "lake", "leaf",
	"moon", "mud", "ocean", "peak", "pine", "pond", "rain", "reef", "river", "rock", "sand", "sea", "shore", "sky", "snow", "star",
	"stone", "storm", "stream", "sun", "swamp", "thorn", "tide", "tree", "valley", "wave", "wind", "wood", "anchor", "arrow", "axe", "bell",
	"belt", "boat", "bone", "book", "boot", "bottle", "bowl", "box", "brick", "bridge", "brush", "bucket", "button", "cable", "camera", "candle",
	"canoe", "card", "chain", "chair", "chalk", "clock", "coin", "comb", "cup", "desk", "dish", "door", "drum", "fork", "glass", "glove",
	"hammer", "harp", "hat", "helmet", "hook", "horn", "jar", "kettle", "key", "kite", "knife", "ladder", "lamp", "lock", "map", "mask",
	"medal", "mirror", "nail", "needle", "net", "oar", "paint", "paper", "pen", "piano", "pillow", "pipe", "plate", "pot", "rope", "saddle",
	"sail", "scarf", "shell", "shield", "shoe", "sock", "spoon", "stamp", "straw", "sword", "table", "tent", "ticket", "tower", "towel", "train",
	"truck", "tube", "violin", "wagon", "wallet", "watch", "wheel", "whip", "window", "wire", "yarn", "zipper", "atom", "bolt", "cliff", "crown",
}
