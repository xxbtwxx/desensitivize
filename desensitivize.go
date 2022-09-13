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

	objValue := reflect.ValueOf(objCopy)
	objType := objValue.Type()
	objKind := objType.Kind()

	switch objKind {
	case reflect.Struct:
		return *redact(objValue).Interface().(*T)
	case reflect.Pointer:
		return handlePointer(objValue).Interface().(T)
	case reflect.Array, reflect.Slice:
		return handleIteratable(objValue).Interface().(T)
	case reflect.Map:
		return handleMap(objValue).Interface().(T)
	}

	return obj
}

func handleIteratable(obj reflect.Value) reflect.Value {
	if obj.Kind() == reflect.Pointer {
		obj = obj.Elem()
	}

	for i := 0; i < obj.Len(); i++ {
		indexVal := obj.Index(i)
		indexKind := indexVal.Kind()

		switch indexKind {
		case reflect.Struct:
			redactedVal := redact(indexVal)
			indexVal.Set(redactedVal.Elem())
		case reflect.Pointer:
			redactedVal := handlePointer(indexVal)
			indexVal.Elem().Set(redactedVal.Elem())
		case reflect.Slice, reflect.Array:
			redactedVal := handleIteratable(indexVal)
			indexVal.Elem().Set(redactedVal)
		case reflect.Map:
			redactedVal := handleMap(indexVal)
			indexVal.Elem().Set(redactedVal)
		}
	}

	return obj
}

func handleMap(obj reflect.Value) reflect.Value {
	if obj.Kind() == reflect.Pointer {
		obj = obj.Elem()
	}

	keys := obj.MapKeys()
	for _, key := range keys {
		elem := obj.MapIndex(key)
		elemKind := elem.Kind()
		keyKind := key.Kind()
		obj.SetMapIndex(key, reflect.Value{})
		key = handleMapKey(key)

		if key.Kind() == reflect.Pointer && keyKind != reflect.Pointer {
			key = key.Elem()
		}

		switch elemKind {
		case reflect.Struct:
			obj.SetMapIndex(key, redact(elem).Elem())
		case reflect.Pointer:
			obj.SetMapIndex(key, handlePointer(elem))
		case reflect.Slice, reflect.Array:
			obj.SetMapIndex(key, handleIteratable(elem))
		case reflect.Map:
			obj.SetMapIndex(key, handleMap(elem))
		}
	}
	return obj
}

func handlePointer(obj reflect.Value) reflect.Value {
	objType := obj.Type()
	objKind := objType.Elem().Kind()

	switch objKind {
	case reflect.Struct:
		return redact(obj.Elem())
	case reflect.Pointer:
		redactedValue := handlePointer(obj)
		tmpObj := reflect.New(objType)
		tmpObj.Elem().Set(redactedValue)
		return tmpObj
	case reflect.Array, reflect.Slice:
		redactedValue := handleIteratable(obj)
		tmpObj := reflect.New(objType.Elem())
		tmpObj.Elem().Set(redactedValue)
		return tmpObj
	case reflect.Map:
		return handleMap(obj)
	}

	return obj
}

func handleMapKey(key reflect.Value) reflect.Value {
	typeOf := key.Type()
	kind := typeOf.Kind()

	switch kind {
	case reflect.Struct:
		return redact(key)
	case reflect.Array, reflect.Slice:
		return handleIteratable(key)
	case reflect.Map:
		return handleMapKey(key)
	case reflect.Pointer:
		return handlePointer(key)
	}
	return key
}

func redact(obj reflect.Value) reflect.Value {
	if obj.Type().Kind() != reflect.Ptr {
		tmpObj := reflect.New(obj.Type())

		tmpObj.Elem().Set(obj)

		obj = tmpObj
	}

	objType := obj.Type()
	for i := 0; i < objType.Elem().NumField(); i++ {
		fieldVal := obj.Elem().Field(i)

		if _, exist := objType.Elem().Field(i).Tag.Lookup("sensitive"); exist {
			fieldVal.Set(reflect.Zero(fieldVal.Type()))
			continue
		}

		fieldKind := fieldVal.Kind()
		switch fieldKind {
		case reflect.Struct:
			redactedVal := redact(fieldVal)
			fieldVal.Set(redactedVal.Elem())
		case reflect.Array, reflect.Slice:
			redactedVal := handleIteratable(fieldVal)
			fieldVal.Set(redactedVal)
		case reflect.Map:
			redactedVal := handleMap(fieldVal)
			fieldVal.Set(redactedVal)
		case reflect.Pointer:
			redactedVal := handlePointer(fieldVal)
			fieldVal.Set(redactedVal)
		}
	}

	return obj
}
