;; Copyright © 2022, JUXT LTD.

(ns juxt.pass.authorization-explainer-test
  (:require
   [clojure.test :refer [deftest is are testing use-fixtures] :as t]
   [juxt.test.util :refer [with-xt with-handler submit-and-await!
                           *xt-node* *handler*]]
   [xtdb.api :as xt]))

(alias 'pass (create-ns 'juxt.pass.alpha))
(alias 'site (create-ns 'juxt.site.alpha))

(use-fixtures :each with-xt)

;; As a warmup, let's start with some contrived data and demonstrate how
;; authorization works in Site.

;; In Site's authorization system, a subject might cause an action on a resource
;; (which would change it in some way). The authorization system must first
;; check that the subject (user) is allowed to cause a given action on the
;; resource.

;; A long time ago, web servers supported 'user directories'. If you had an
;; account on a host and your username was 'alice', you could put files into a
;; public_html directory in your home directory and this would be published over
;; the WWW under http://host/~alice/. The tilde (~) indicates that the files
;; belong to the account owner. See
;; https://httpd.apache.org/docs/2.4/howto/public_html.html for further details.

;; We'll create a similar system here, using subjects/actions/resources.

(defn check-permissions
  "Given a subject, an action and resource, return all related permissions."
  [db subject action resource rules]
  (xt/q
   db
   {:find '[permission]
    :where
    '[
      [permission ::site/type "Permission"]
      [action ::site/type "Action"]
      [permission ::pass/action action]
      (allowed? permission subject action resource)]

    :rules rules

    :in '[subject action resource]}

   subject action resource))

(defn allowed-resources
  "Given a subject and a set of possible actions, which resources are allowed?"
  [db subject actions rules]
  (xt/q
   db
   {:find '[resource]
    :where
    '[
      [permission ::site/type "Permission"]
      [action ::site/type "Action"]
      [permission ::pass/action action]
      [(contains? actions action)]

      (allowed? permission subject action resource)]

    :rules rules

    :in '[subject actions]}

   subject actions))

(def ALICE
  {:xt/id "https://example.org/people/alice",
   ::site/type "User"
   ::username "alice"})

(def BOB
  {:xt/id "https://example.org/people/bob",
   ::site/type "User"
   ::username "bob"})

(def CARL
  {:xt/id "https://example.org/people/carl",
   ::site/type "User"
   ::username "carl"})

(def ALICE_USER_DIR_PRIVATE_FILE
  {:xt/id "https://example.org/~alice/private.txt"
   ::site/type "Resource"})

(def ALICE_USER_DIR_SHARED_FILE
  {:xt/id "https://example.org/~alice/shared.txt"
   ::site/type "Resource"})

(def READ_USER_DIR_ACTION
  {:xt/id "https://example.org/actions/read-user-dir"
   ::site/type "Action"
   ::pass/resource-matches "https://example.org/~([a-z]+)/.+"})

(def WRITE_USER_DIR_ACTION
  {:xt/id "https://example.org/actions/write-user-dir"
   ::site/type "Action"
   ::pass/resource-matches "https://example.org/~([a-z]+)/.+"
   ::pass/action-args [{}]})

(def READ_SHARED_ACTION
  {:xt/id "https://example.org/actions/read-shared"
   ::site/type "Action"})

(def ALICE_CAN_READ
  {:xt/id "https://example.org/permissions/alice-can-read"
   ::site/type "Permission"
   ::pass/subject "https://example.org/people/alice"
   ::pass/action #{"https://example.org/actions/read-shared"
                   "https://example.org/actions/read-user-dir"}})

(def ALICE_CAN_WRITE_USER_DIR_CONTENT
  {:xt/id "https://example.org/permissions/alice-can-write-user-dir-content"
   ::site/type "Permission"
   ::pass/subject "https://example.org/people/alice"
   ::pass/action #{"https://example.org/actions/write-user-dir"}})

(def BOB_CAN_READ
  {:xt/id "https://example.org/permissions/bob-can-read"
   ::site/type "Permission"
   ::pass/subject "https://example.org/people/bob"
   ::pass/action #{"https://example.org/actions/read-shared"
                   "https://example.org/actions/read-user-dir"}})

(def ALICES_SHARES_FILE_WITH_BOB
  {:xt/id "https://example.org/permissions/alice-shares-file-with-bob"
   ::site/type "Permission"
   ::pass/subject "https://example.org/people/bob"
   ::pass/action "https://example.org/actions/read-shared"
   ::pass/resource "https://example.org/~alice/shared.txt"})

(def BOB_CAN_WRITE_USER_DIR_CONTENT
  {:xt/id "https://example.org/permissions/bob-can-write-user-dir-content"
   ::site/type "Permission"
   ::pass/subject "https://example.org/people/bob"
   ::pass/action #{"https://example.org/actions/write-user-dir"}})

(def WRITE_USER_DIR_RULES
  '[[(allowed? permission subject action resource)
     [permission ::pass/subject subject]
     [action :xt/id "https://example.org/actions/write-user-dir"]
     [action ::pass/resource-matches resource-regex]
     [subject ::username username]
     [(re-pattern resource-regex) resource-pattern]
     [(re-matches resource-pattern resource) [_ user]]
     [(= user username)]]])

(def READ_USER_DIR_RULES
  '[[(allowed? permission subject action resource)
     [permission ::pass/subject subject]
     [action :xt/id "https://example.org/actions/read-user-dir"]
     [action ::pass/resource-matches resource-regex]
     [subject ::username username]
     [resource ::site/type "Resource"]
     [(re-pattern resource-regex) resource-pattern]
     [(re-matches resource-pattern resource) [_ user]]
     [(= user username)]]])

(def READ_SHARED_RULES
  '[[(allowed? permission subject action resource)
     [permission ::pass/subject subject]
     [action :xt/id "https://example.org/actions/read-shared"]
     [permission ::pass/resource resource]]])

(deftest user-dir-test
  (submit-and-await!
   [
    [::xt/put ALICE]
    [::xt/put BOB]
    [::xt/put CARL]
    [::xt/put ALICE_USER_DIR_PRIVATE_FILE]
    [::xt/put ALICE_USER_DIR_SHARED_FILE]
    [::xt/put READ_USER_DIR_ACTION]
    [::xt/put READ_SHARED_ACTION]
    [::xt/put WRITE_USER_DIR_ACTION]
    [::xt/put ALICE_CAN_READ]
    [::xt/put ALICE_CAN_WRITE_USER_DIR_CONTENT]
    [::xt/put ALICES_SHARES_FILE_WITH_BOB]
    [::xt/put BOB_CAN_READ]
    [::xt/put BOB_CAN_WRITE_USER_DIR_CONTENT]])

  (let [rules (vec (concat WRITE_USER_DIR_RULES READ_USER_DIR_RULES READ_SHARED_RULES))
        db (xt/db *xt-node*)]

    (are [subject action resource ok?]
        (let [actual (check-permissions db subject action resource rules)]
          (if ok? (is (seq actual)) (is (not (seq actual)))))

      ;; Alice can read her own private file.
      "https://example.org/people/alice"
      "https://example.org/actions/read-user-dir"
      "https://example.org/~alice/private.txt"
      true

      ;; Alice can read the file in her user directory which she has shared with
      ;; Bob.
      "https://example.org/people/alice"
      "https://example.org/actions/read-user-dir"
      "https://example.org/~alice/shared.txt"
      true

      ;; Bob cannot read Alice's private file.
      "https://example.org/people/bob"
      "https://example.org/actions/read-user-dir"
      "https://example.org/~alice/private.txt"
      false

      ;; Bob can read the file Alice has shared with him.
      "https://example.org/people/bob"
      "https://example.org/actions/read-shared"
      "https://example.org/~alice/shared.txt"
      true

      ;; Alice can put a file to her user directory
      "https://example.org/people/alice"
      "https://example.org/actions/write-user-dir"
      "https://example.org/~alice/foo.txt"
      true

      ;; Alice can't put a file to Bob's user directory
      "https://example.org/people/alice"
      "https://example.org/actions/write-user-dir"
      "https://example.org/~bob/foo.txt"
      false

      ;; Alice can't put a file outside her user directory
      "https://example.org/people/alice"
      "https://example.org/actions/write-user-dir"
      "https://example.org/index.html"
      false

      ;; Bob can put a file to his user directory
      "https://example.org/people/bob"
      "https://example.org/actions/write-user-dir"
      "https://example.org/~bob/foo.txt"
      true

      ;; Bob can't put a file to Alice's directory
      "https://example.org/people/bob"
      "https://example.org/actions/write-user-dir"
      "https://example.org/~alice/foo.txt"
      false

      ;; Carl cannot put a file to his user directory, as he hasn't been
      ;; granted the write-user-dir action.
      "https://example.org/people/carl"
      "https://example.org/actions/write-user-dir"
      "https://example.org/~carl/foo.txt"
      false)

    (is (= #{["https://example.org/~alice/shared.txt"]
             ["https://example.org/~alice/private.txt"]}
           (allowed-resources
            db
            "https://example.org/people/alice"
            #{"https://example.org/actions/read-user-dir"
              "https://example.org/actions/read-shared"}
            (vec (concat READ_USER_DIR_RULES READ_SHARED_RULES)))))

    (is (= #{["https://example.org/~alice/shared.txt"]}
           (allowed-resources
            db
            "https://example.org/people/bob"
            #{"https://example.org/actions/read-user-dir"
              "https://example.org/actions/read-shared"}
            (vec (concat READ_USER_DIR_RULES READ_SHARED_RULES)))))))
