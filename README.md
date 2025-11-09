# stix2api

## Overview

Our ambition is to create a Cyber Threat Exchange that allows;

1. producers to create/submit their intelligence into the exchange
2. consumers to subscribe to a producers feed(s) using a REST / TAXII API.

In order to that, we need a flexible, but structured way for producers to submit their intel and for users to explore it.

stix2api is the core API that will support this.

## Why not just use the stix2 Python library

Our need for something more custom stems from two main requirements:

1. We want to expose this via a web app
2. We want to allows users to use custom objects/properties in a controlled way (via our [stix2extensions](https://github.com/muchdogesec/stix2extensions) repository)
 
## Endpoints

### Global search

* GET `search/`
	* filters: `text`
	* this endpoint is designed to be a simple search through all objects and properties to match string. It's main aim is to provide a basic search interface to retrieve objects (vs. very specific object searches)

### Objects

For each object type there will be the following available endpoints:

* GET `<STIX TYPE>/<OBJECT TYPE>` (e.g. `sdo/attack-pattern/`): Object search
	* returns all objects that match the type and filters
	* filters: for all properties defined in the core schema + any registered extensions in stix2extensions + pagination + visible_to (not for SCOs)
	* note: this endpoint exists, because each type has lots of different property names to search on, so a global search is not super simple
* GET `<STIX TYPE>/<OBJECT TYPE>/<ID>` (e.g. `sdo/attack-pattern/attack-pattern--3ce78b4c-273f-43ea-a2ba-a0755ba8e3c7`): Single object lookup
	* has filters to define the specific version + visible_to (not for SCOs)
* GET `<STIX TYPE>/<OBJECT TYPE>/<ID>/versions` (e.g. `sdo/attack-pattern/attack-pattern--3ce78b4c-273f-43ea-a2ba-a0755ba8e3c7/versions`: Version search
	* returns a list of all versions of the object in the database
	* filters: visible_to (not for SCOs)
* GET `<STIX TYPE>/<OBJECT TYPE>/<ID>/bundle` (e.g. `sdo/attack-pattern/attack-pattern--3ce78b4c-273f-43ea-a2ba-a0755ba8e3c7/bundle`: Bundle generation
	* returns a bundle of objects related to the one defined 
	* filters: visible_to (not for SCOs), include_embedded, type
* POST `<STIX TYPE>/<OBJECT TYPE>/<ID>`
	* allows a user to add a new object
* PATCH `<STIX TYPE>/<OBJECT TYPE>/<ID>`

### Mass Upload

* POST `bundle/`

#### A note on POST behaviour (for SDO/SRO/SCO types)

* all objects will be validated against the core schema, and all registered property extensions for the object type
	* if they do not conform (i.e. required values missing or incorrect properties/value types passed), the API will return 400 responses immediatley
	* we lookup custom properties only if an extension defintion passed. The ED must be registered on the current main release of stix2extensions
* user can pass any `created` and `modified` time
* user can pass any `id` value
	* if `id` conflicts return 403. Stating this object exists and should use PATCH
* allow user to pass hidden properties (we should define the list of hidden properties needed)

#### A note on POST behaviour (for SCO types)

* we should allow user to pass a hidden `_created_by_ref` property that can be used to control ownership

#### A note on PATCH behaviour (for SDO/SRO types)

* user cannot modify `id`, `type`, `created`, `modified`, `created_by_ref` or `spec_version`
* For SDO and SRO objects on all successful modifications the `modified` time will be automatically update to match the execution time of the change

#### A note on PATCH behaviour (for SCO types)

* user cannot modify `id`, `type`, `_created_by_ref`
* we should allow user to pass `_created_by_ref` in each request (optionally to validate ownership, and stop request if owner does not match `_created_by_ref` -- this is mainly to control edits of SCOs in web)

#### A note on bundle upload behaviour

* will store bundle id against notes of each object, note, this could be more than one bundle when object id updated more than one time
* for bundle upload, all objects will be first parsed out, they will then one by one be added using the appropriate POST object endpoints
* this will be considered as one job, if one or more objects in upload fail the job will continue. All successes and errors will be reported in the job individually so it is clear what objects failed (and why), and which uploaded successfully.

### Jobs

All POST and PATCH request will be tracked as jobs to highlight any errors on insert to db.

We will expose `job/` and `job/<ID>` to allow user to get info of their requests,

## Support

[Minimal support provided via the dogesec community](https://community.dogesec.com/).

## License

[Apache 2.0](/LICENSE).