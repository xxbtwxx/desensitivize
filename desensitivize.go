package desensitivize

import (
	"bytes"
	"encoding/gob"
	"reflect"
)

func copyObj[T any](obj T) (objCopy T) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)

	enc.Encode(obj)
	dec.Decode(&objCopy)

	return
}

func Redact[T any](obj T) T {
	objCopy := copyObj(obj)

	interfaceValue := reflect.ValueOf(objCopy).Interface()
	typeOf := reflect.TypeOf(interfaceValue)
	kind := typeOf.Kind()

	switch {
	case kind == reflect.Array || kind == reflect.Slice:
		return handleIteratable(interfaceValue).(T)
	case kind == reflect.Map:
		return handleMap(interfaceValue).(T)
	case kind == reflect.Pointer || kind == reflect.UnsafePointer:
		return handlePointer(interfaceValue).(T)
	case kind == reflect.Struct:
		return *redact(interfaceValue).(*T)
	}

	return interfaceValue.(T)
}

func handleIteratable(obj any) any {
	valueOf := reflect.ValueOf(obj)
	if valueOf.Kind() == reflect.Ptr {
		valueOf = valueOf.Elem()
	}

	for i := 0; i < valueOf.Len(); i++ {
		elem := valueOf.Index(i)
		elemInterface := elem.Interface()
		elemKind := elem.Kind()

		switch {
		case elemKind == reflect.Array || elemKind == reflect.Slice:
			elemValue := reflect.ValueOf(handleIteratable(elemInterface))
			elem.Set(elemValue)
		case elemKind == reflect.Map:
			elemValue := reflect.ValueOf(handleMap(elemInterface))
			elem.Set(elemValue)
		case elemKind == reflect.Pointer || elemKind == reflect.UnsafePointer:
			elemValue := reflect.ValueOf(handlePointer(elemInterface))
			if elemValue.Kind() != reflect.Pointer {
				elem.Elem().Set(elemValue)
			} else {
				elem.Set(elemValue)
			}
		case elemKind == reflect.Struct:
			elemValue := reflect.ValueOf(redact(elemInterface))
			elem.Set(elemValue.Elem())
		}
	}

	return obj
}

func handleMap(obj any) any {
	valueOf := reflect.ValueOf(obj)
	if valueOf.Kind() == reflect.Ptr {
		valueOf = valueOf.Elem()
	}

	keys := valueOf.MapKeys()
	for _, key := range keys {
		elem := valueOf.MapIndex(key)
		elemInterface := elem.Interface()
		elemKind := elem.Kind()

		valueOf.SetMapIndex(key, reflect.Value{})
		keyInterface := handleMapKey(key.Interface())
		key = reflect.ValueOf(keyInterface)

		switch {
		case elemKind == reflect.Array || elemKind == reflect.Slice:
			elemValue := reflect.ValueOf(handleIteratable(elemInterface))
			valueOf.SetMapIndex(key, elemValue)
		case elemKind == reflect.Map:
			elemValue := reflect.ValueOf(handleMap(elemInterface))
			if elemValue.Kind() != reflect.Pointer {
				elem.Elem().SetMapIndex(key, elemValue)
			} else {
				elem.SetMapIndex(key, elemValue)
			}
		case elemKind == reflect.Pointer || elemKind == reflect.UnsafePointer:
			elemValue := reflect.ValueOf(handlePointer(elemInterface))
			if elemValue.Kind() != reflect.Pointer {
				valueOf.SetMapIndex(key, elemValue.Elem())
			} else {
				valueOf.SetMapIndex(key, elemValue)
			}
		case elemKind == reflect.Struct:
			elemValue := reflect.ValueOf(redact(elemInterface))
			valueOf.SetMapIndex(key, elemValue.Elem())
		}
	}

	return obj
}

func handlePointer(obj any) any {
	typeOf := reflect.TypeOf(obj)
	kind := typeOf.Elem().Kind()
	valueOf := reflect.ValueOf(obj).Elem().Interface()

	switch {
	case kind == reflect.Array || kind == reflect.Slice:
		handledValue := handleIteratable(valueOf)
		tmpObj := reflect.New(reflect.TypeOf(handledValue))
		tmpObj.Elem().Set(reflect.ValueOf(handledValue))
		return tmpObj.Interface()
	case kind == reflect.Map:
		handledValue := handleMap(valueOf)
		tmpObj := reflect.New(reflect.TypeOf(handledValue))
		tmpObj.Elem().Set(reflect.ValueOf(handledValue))
		return tmpObj.Interface()
	case kind == reflect.Pointer || kind == reflect.UnsafePointer:
		handledValue := handlePointer(valueOf)
		tmpObj := reflect.New(reflect.TypeOf(handledValue))
		tmpObj.Elem().Set(reflect.ValueOf(handledValue))
		return tmpObj.Interface()
	case kind == reflect.Struct:
		return redact(valueOf)
	}

	return obj
}

func handleMapKey(key any) any {
	typeOf := reflect.TypeOf(key)
	kind := typeOf.Kind()

	switch {
	case kind == reflect.Array || kind == reflect.Slice:
		return handleIteratable(key)
	case kind == reflect.Map:
		return handleMap(key)
	case kind == reflect.Pointer || kind == reflect.UnsafePointer:
		return handlePointer(key)
	case kind == reflect.Struct:
		return reflect.ValueOf(redact(key)).Elem().Interface()
	}

	return key
}

func redact(obj any) any {
	if reflect.TypeOf(obj).Kind() != reflect.Ptr {
		tmpObj := reflect.New(reflect.TypeOf(obj))
		tmpObj.Elem().Set(reflect.ValueOf(obj))

		obj = tmpObj.Interface()
	}

	v := reflect.ValueOf(obj).Elem()
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		fieldVal := v.Field(i)

		kind := fieldVal.Type().Kind()
		fieldValInt := fieldVal.Interface()

		switch {
		case kind == reflect.Struct:
			redactedVal := redact(fieldValInt)
			fieldVal.Set(reflect.ValueOf(redactedVal).Elem())
		case kind == reflect.Array || kind == reflect.Slice:
			redactedVal := handleIteratable(fieldValInt)
			fieldVal.Set(reflect.ValueOf(redactedVal))
		case kind == reflect.Pointer || kind == reflect.UnsafePointer:
			redactedVal := handlePointer(fieldValInt)
			fieldVal.Set(reflect.ValueOf(redactedVal))
		case kind == reflect.Map:
			redactedVal := handleMap(fieldValInt)
			fieldVal.Set(reflect.ValueOf(redactedVal))
		}

		if _, exist := t.Field(i).Tag.Lookup("sensitive"); !exist {
			continue
		}

		fieldVal.Set(reflect.Zero(fieldVal.Type()))
	}

	return obj
}
