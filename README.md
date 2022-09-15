# desensitivize
A library for redacting sensitive info from data containers

## Usage
Sensify works by parsing struct tags. In order to remove sensitive data from your structs they need to have a `sensitive` tag. Note that the value of the tag is irrelevant.

### Constraints
The library works with all kinds of data containers: structs, slices, arrays, maps and pointers to these containers.
Passing other type of data would result in a overhead due to making a copy of the object.

### Example
```golang
type SomeStruct struct {
  FieldA string
  FieldB string `sensitive:"-"`
}

func doStuff(someStruct SomeStruct) {
  fmt.Println(someStruct)
  removedSensitiveDataStruct := desensitivize.Redact(someStruct)
  fmt.Println(removedSensitiveDataStruct)
  fmt.Println(someStruct)
}

func main() {
  someStruct := SomeStruct{
    FieldA: "field A data",
    FieldB: "field B sensitive data",
  }
  
  doStuff(someStruct)
}
```

The output of the following code would be the following one
```
{field A data field B sensitive data}
{field A data }
{field A data field B sensitive data}
```

### Beware
If you pass a map with `struct` keys which struct has fields marked as `sensitive` it would redact the keys too which may lead to collisions and loss of data
