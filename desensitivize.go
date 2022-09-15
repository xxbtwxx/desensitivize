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
		return *handleStruct(objValue).Interface().(*T)
	case reflect.Pointer:
		return handlePointer(objValue).Interface().(T)
	case reflect.Slice:
		return handleSlice(objValue).Interface().(T)
	case reflect.Map:
		return handleMap(objValue).Interface().(T)
	case reflect.Array:
		return *handleArray(objValue).Interface().(*T)
	}

	return obj
}

func handleSlice(obj reflect.Value) reflect.Value {
	if obj.Kind() == reflect.Pointer {
		obj = obj.Elem()
	}

	for i := 0; i < obj.Len(); i++ {
		indexVal := obj.Index(i)
		indexKind := indexVal.Kind()

		switch indexKind {
		case reflect.Struct:
			indexVal.Set(handleStruct(indexVal).Elem())
		case reflect.Pointer:
			indexVal.Elem().Set(handlePointer(indexVal).Elem())
		case reflect.Slice:
			indexVal.Set(handleSlice(indexVal))
		case reflect.Map:
			indexVal.Set(handleMap(indexVal))
		case reflect.Array:
			indexVal.Set(handleArray(indexVal).Elem())
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
			obj.SetMapIndex(key, handleStruct(elem).Elem())
		case reflect.Pointer:
			obj.SetMapIndex(key, handlePointer(elem))
		case reflect.Slice:
			obj.SetMapIndex(key, handleSlice(elem))
		case reflect.Map:
			obj.SetMapIndex(key, handleMap(elem))
		case reflect.Array:
			obj.SetMapIndex(key, handleArray(elem).Elem())
		}
	}
	return obj
}

func handlePointer(obj reflect.Value) reflect.Value {
	if obj.IsNil() {
		return obj
	}

	objType := obj.Type()
	objKind := objType.Elem().Kind()

	switch objKind {
	case reflect.Struct:
		return handleStruct(obj.Elem())
	case reflect.Pointer:
		redactedValue := handlePointer(obj.Elem())
		tmpObj := reflect.New(redactedValue.Type())
		tmpObj.Elem().Set(redactedValue)
		return tmpObj
	case reflect.Slice:
		redactedValue := handleSlice(obj)
		tmpObj := reflect.New(objType.Elem())
		tmpObj.Elem().Set(redactedValue)
		return tmpObj
	case reflect.Map:
		redactedValue := handleMap(obj)
		tmpObj := reflect.New(objType.Elem())
		tmpObj.Elem().Set(redactedValue)
		return tmpObj
	case reflect.Array:
		redactedValue := handleArray(obj.Elem())
		tmpObj := reflect.New(objType.Elem())
		tmpObj.Elem().Set(redactedValue.Elem())
		return tmpObj
	}

	return obj
}

func handleMapKey(key reflect.Value) reflect.Value {
	typeOf := key.Type()
	kind := typeOf.Kind()

	switch kind {
	case reflect.Struct:
		return handleStruct(key)
	case reflect.Array:
		return handleArray(key)
	case reflect.Pointer:
		return handlePointer(key)
	}
	return key
}

func handleArray(obj reflect.Value) reflect.Value {
	tempArr := reflect.New(reflect.ArrayOf(obj.Len(), obj.Index(0).Type()))
	for i := 0; i < obj.Len(); i++ {
		element := obj.Index(i)
		newEl := tempArr.Elem().Index(i)
		elementKind := element.Kind()

		switch elementKind {
		case reflect.Struct:
			newEl.Set(handleStruct(element).Elem())
		case reflect.Array:
			newEl.Set(handleArray(element).Elem())
		case reflect.Map:
			newEl.Set(handleMap(element))
		case reflect.Pointer:
			newEl.Set(handlePointer(element))
		case reflect.Slice:
			newEl.Set(handleSlice(element))
		}
	}

	return tempArr
}

func handleStruct(obj reflect.Value) reflect.Value {
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
			redactedVal := handleStruct(fieldVal)
			fieldVal.Set(redactedVal.Elem())
		case reflect.Slice:
			fieldVal.Set(handleSlice(fieldVal))
		case reflect.Map:
			fieldVal.Set(handleMap(fieldVal))
		case reflect.Pointer:
			fieldVal.Set(handlePointer(fieldVal))
		case reflect.Array:
			fieldVal.Set(handleArray(fieldVal).Elem())
		}
	}

	return obj
}
