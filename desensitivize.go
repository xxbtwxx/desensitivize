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

	switch kind {
	case reflect.Array, reflect.Slice:
		return handleIteratable(interfaceValue).(T)
	case reflect.Map:
		return handleMap(interfaceValue).(T)
	case reflect.Pointer, reflect.UnsafePointer:
		return handlePointer(interfaceValue).(T)
	case reflect.Struct:
		return *redact(interfaceValue).(*T)
	default:
		return interfaceValue.(T)
	}
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

		switch elemKind {
		case reflect.Array, reflect.Slice:
			elemValue := reflect.ValueOf(handleIteratable(elemInterface))
			elem.Set(elemValue)
		case reflect.Map:
			elemValue := reflect.ValueOf(handleMap(elemInterface))
			elem.Set(elemValue)
		case reflect.Pointer, reflect.UnsafePointer:
			elemValue := reflect.ValueOf(handlePointer(elemInterface))
			if elemValue.Kind() != reflect.Pointer {
				elem.Elem().Set(elemValue)
			} else {
				elem.Set(elemValue)
			}
		case reflect.Struct:
			elemValue := reflect.ValueOf(redact(elemInterface))
			elem.Set(elemValue.Elem())
		default:
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

		switch elemKind {
		case reflect.Array, reflect.Slice:
			elemValue := reflect.ValueOf(handleIteratable(elemInterface))
			valueOf.SetMapIndex(key, elemValue)
		case reflect.Map:
			elemValue := reflect.ValueOf(handleMap(elemInterface))
			if elemValue.Kind() != reflect.Pointer {
				elem.Elem().SetMapIndex(key, elemValue)
			} else {
				elem.SetMapIndex(key, elemValue)
			}
		case reflect.Pointer, reflect.UnsafePointer:
			elemValue := reflect.ValueOf(handlePointer(elemInterface))
			if elemValue.Kind() != reflect.Pointer {
				valueOf.SetMapIndex(key, elemValue.Elem())
			} else {
				valueOf.SetMapIndex(key, elemValue)
			}
		case reflect.Struct:
			elemValue := reflect.ValueOf(redact(elemInterface))
			valueOf.SetMapIndex(key, elemValue.Elem())
		default:
		}
	}

	return obj
}

func handlePointer(obj any) any {
	typeOf := reflect.TypeOf(obj)
	kind := typeOf.Elem().Kind()
	valueOf := reflect.ValueOf(obj).Elem().Interface()

	switch kind {
	case reflect.Array, reflect.Slice:
		handledValue := handleIteratable(valueOf)
		tmpObj := reflect.New(reflect.TypeOf(handledValue))
		tmpObj.Elem().Set(reflect.ValueOf(handledValue))
		return tmpObj.Interface()
	case reflect.Map:
		handledValue := handleMap(valueOf)
		tmpObj := reflect.New(reflect.TypeOf(handledValue))
		tmpObj.Elem().Set(reflect.ValueOf(handledValue))
		return tmpObj.Interface()
	case reflect.Pointer, reflect.UnsafePointer:
		handledValue := handlePointer(valueOf)
		tmpObj := reflect.New(reflect.TypeOf(handledValue))
		tmpObj.Elem().Set(reflect.ValueOf(handledValue))
		return tmpObj.Interface()
	case reflect.Struct:
		return redact(valueOf)
	default:
		return obj
	}
}

func handleMapKey(key any) any {
	typeOf := reflect.TypeOf(key)
	kind := typeOf.Kind()

	switch kind {
	case reflect.Array, reflect.Slice:
		return handleIteratable(key)
	case reflect.Map:
		return handleMap(key)
	case reflect.Pointer, reflect.UnsafePointer:
		return handlePointer(key)
	case reflect.Struct:
		return reflect.ValueOf(redact(key)).Elem().Interface()
	default:
		return key
	}
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

		switch kind {
		case reflect.Struct:
			redactedVal := redact(fieldValInt)
			fieldVal.Set(reflect.ValueOf(redactedVal).Elem())
		case reflect.Array, reflect.Slice:
			redactedVal := handleIteratable(fieldValInt)
			fieldVal.Set(reflect.ValueOf(redactedVal))
		case reflect.Pointer, reflect.UnsafePointer:
			redactedVal := handlePointer(fieldValInt)
			fieldVal.Set(reflect.ValueOf(redactedVal))
		case reflect.Map:
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
