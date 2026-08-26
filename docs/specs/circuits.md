
## Serializing a Circuit
A circuit structure consists of size metadata, a table of constants, and an array of structures that represent the layers of the circuit as follows.

```
struct {
  Version version;     // 1-byte identifier, 0x1.
  FieldID field;       // identifies the field
  FieldID subfield;    // identifies the subfield
  size num_outputs;    // number of outputs
  size pub_in;         // number of public inputs
  size ninputs;        // number of inputs, including witnesses
  size num_layers;     // number of layers
  Elt const_table[];   // array of constants used by the quads
  CircuitLayer layers[]; 	// array of layers of size num_layers
} Circuit;
```

The `const_table` structure contains an array of `Elt` constants that can be referred by any of the CircuitLayer structures. This feature saves space because a typical circuit uses only a handful of constants, which can be referred by a small index value into this table.

```
struct {
  size log_num_input_wires;  // log of number of wires
  size num_input_wires;      // number of wires
  Quads quads[];             // array of Quads
} CircuitLayer;
```

The `quads` array stores the main portion of the circuit. Each `Quad` structure contains a g, h0, h1 and a constant `v` which is represented as an index into the `const_table` array in the `Circuit`.  Each `g`,`h0`, and `h1` is stored as a difference from the corresponding item in the *previous* quad. In other words, these three values are delta-encoded in order to improve the compressibility of the circuit representation. The Delta spec uses LSB as a sign bit to indicate negative numbers.

```
struct {
  Delta g;     // delta-encoded gate number
  Delta h0;    // delta-encoded left wire index
  Delta h1;    // delta-encoded right wire index
  size v;      // index into the const_table to specify const v
} Quad;

typedef Delta uint;
```