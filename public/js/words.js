/**
 * Passphrase wordlist.
 *
 * Short, common, unambiguous English words. Easy to read off a screen and type
 * on a phone keyboard. The generator computes entropy from the real length of
 * this list after de-duplication, so the strength it reports stays honest even
 * if the list is edited.
 */

const RAW = `
able acid acorn actor adapt adult agent agree alarm album alert alley almond alpha
amber amuse angel angle ankle apple arbor arch arena argue armor array arrow aside
asset atlas atom attic audio auto avoid awake award axis bacon badge bagel baker
ball bamboo banjo barge basil basin batch beach beam bean bear bench berry bike
birch bird bison black blade blank blaze blend blink bloom blue board boat bold
bolt bone bonus book boost booth borrow bottle boulder brain branch brass brave
bread brick bridge brief bright bronze brook brush bubble bucket buffalo bundle
cabin cable cactus camel candle canoe canvas canyon carbon cargo carpet carrot
castle cedar cello chalk charm cheese cherry chess chime cider cinder circle citrus
civic clamp clay clever cliff cloak clock cloud clover coast cobalt cocoa coffee
coin comet compass copper coral cotton couch cousin cove coyote crane crate crayon
cream credit crisp crown crystal cube cactus curve cycle dagger daisy damp dancer
dawn deal debate decade deck decoy deep deer delta denim depot desert desk detail
diary diesel digit dinner dolphin domain donkey donut double dove dozen draft
dragon drama dream drift drum dryer eagle early earth easel east echo edge eight
elbow elder electric elegant elm ember emerald empty enamel engine enjoy enter
envoy equal escape estate ether event exact exit fabric falcon fancy farm feather
fern ferry fiber fiddle field fierce fifty film filter final finch fir flag flame
flask fleet flint float flour flower fluid flute foam focus foggy folder forest
forge fossil found fox frame fresh frog frost fruit fudge fuel garden garlic gate
gauge gazelle gear gentle giant ginger giraffe glacier glass globe glove glow
golden goose grain grand granite grape graph grass gravel green grid grove guitar
gulf habit hammer hamster harbor hare harvest hazel heart hedge helmet herb heron
hickory hidden hill hinge hobby hollow honey hoop horizon horse hotel human humble
hunter hurdle husky ice idea igloo index indigo inland insect iris iron island
ivory jacket jade jaguar jazz jelly jersey jewel jigsaw jolly journal jungle juniper
kayak kettle key kind kite kitten knot koala label ladder lagoon lake lamp lantern
laptop large laser latch laurel lava lavender leaf ledge legend lemon lentil level
lever light lilac lily linen lion liquid lizard llama lobby local locket lodge
lotus lumber lunar lynx magnet mango manor maple marble march marine market marsh
mask meadow melon member mercy metal meteor mica midnight mild milk mimic mineral
mint mirror mist mitten modest module moment monkey moon moral moss motor mountain
mouse muffin mulberry museum music mustard nectar needle nest nickel night nimble
noble north notch novel nugget nurse nutmeg oak oasis ocean octave olive onion
opal orange orbit orchard orchid organ osprey otter outer oval owl oxide oyster
pacific paddle palace palm panda panel paper parade parcel parrot pasta pastel
patch path patient pattern peach peak pearl pebble pedal pelican pencil penguin
pepper perch petal phantom phoenix piano picnic pigeon pilot pine pink pioneer
pistol pitch pixel pizza plane plank plant plaza pledge plum pocket poem polar
pollen pond pony poplar poppy porch portal potato powder prairie prism prize
proud prune public pudding puffin pulse pumpkin puppy purple puzzle pyramid quail
quarry quartz quest quiet quilt quiver rabbit raccoon radar radish rafter rain
ranch random ranger rapid raven ready realm reason rebel recipe record red reef
relay remote rescue resin ribbon rider ridge rifle rim ripple risk river roast
robin rocket rodeo roof rookie room rose rotate round rover royal ruby rudder
rugby ruler runner rustic saddle safari sage sail salmon salt sample sand sapphire
satin sauce savor scale scarf scene school scout script sculpt seal season sedan
seed sequoia serve shadow shale shark shell shelter sheriff shield shine ship
shore short shovel shrimp shrub sierra signal silent silk silver simple siren
sketch skill skirt sky slate sleek sled slice slope small smart smile smoke snail
snake snow soap social socket soda solar solid sonic soup south space spade spark
sparrow spice spider spiral spoon spring spruce square squid stable stage stamp
star steam steel stem step stereo stick stone storm stove strand stream street
strong studio sugar summit sunny sunset surf swan sweet swift swirl sword symbol
table tackle talent tall tango tape target tavern teal teapot temple tender tennis
tent thorn thread thumb thunder tiger timber tiny toast token tomato topaz torch
tortoise total tower town trace track trade trail train trap travel tray treat
tree trend trial tribe trick trout truck trumpet trust tulip tumble tundra tunnel
turtle tusk twig twilight twist ultra umber umbrella uncle under unique unit
update upper urban urchin usual valley valve vanilla vapor vault velvet vendor
venture verse vessel vest vibrant victor video view village vine vinyl violet
viper vision vivid vocal voyage waffle wagon walnut walrus warm wasp watch water
wave weasel weather weave wedge welcome whale wheat wheel whisper white widget
willow window winter wire wisdom wolf wonder wood wool world woven wrist yacht
yard yarn year yellow yield yoga young zebra zenith zephyr zinc zone
`;

/** De-duplicated so the entropy figure the generator reports is the true one. */
export const WORDS = Object.freeze([...new Set(RAW.trim().split(/\s+/))]);
