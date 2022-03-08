;; Copyright © 2022, JUXT LTD.

(ns juxt.pass.alpha.v3.authorization
  (:require
   [xtdb.api :as xt]))

(alias 'pass (create-ns 'juxt.pass.alpha))
(alias 'site (create-ns 'juxt.site.alpha))

(defn check-permissions
  "Given a subject, possible actions and resource, return all related pairs of permissions and actions."
  [db {:keys [subject actions purpose resource rules]}]
  (xt/q
   db
   {:find '[(pull permission [*]) (pull action [*])]
    :keys '[permission action]
    :where
    '[
      [permission ::site/type "Permission"]
      [action ::site/type "Action"]
      [permission ::pass/action action]
      [permission ::pass/purpose purpose]
      [(contains? actions action)]
      (allowed? permission subject action resource)]

    :rules rules

    :in '[subject actions purpose resource]}

   subject actions purpose resource))

(defn allowed-resources
  "Given a subject and a set of possible actions, which resources are allowed?"
  [db {:keys [subject actions purpose rules]}]
  (xt/q
   db
   {:find '[resource]
    :where
    '[
      [permission ::site/type "Permission"]
      [action ::site/type "Action"]
      [permission ::pass/action action]
      [permission ::pass/purpose purpose]
      [(contains? actions action)]

      (allowed? permission subject action resource)]

    :rules rules

    :in '[subject actions purpose]}

   subject actions purpose))

(defn allowed-subjects
  "Given a resource and a set of actions, which subjects can access and via which
  actions?"
  [db {:keys [resource actions purpose rules]}]
  (->> (xt/q
        db
        {:find '[subject action]
         :keys '[subject action]
         :where
         '[
           [permission ::site/type "Permission"]
           [action ::site/type "Action"]
           [permission ::pass/action action]
           [permission ::pass/purpose purpose]
           [(contains? actions action)]

           (allowed? permission subject action resource)]

         :rules rules

         :in '[resource actions purpose]}

        resource actions purpose)))

(defn pull-allowed-resource
  "Given a subject, a set of possible actions and a resource, pull the allowed
  attributes."
  [db {:keys [subject actions purpose resource rules]}]
  (let [check-result (check-permissions
                      db
                      {:subject subject
                       :actions actions
                       :purpose purpose
                       :resource resource
                       :rules rules})
        pull-expr (vec (mapcat
                        (fn [{:keys [action]}]
                          (::pass/pull action))
                        check-result))]
    (xt/pull db pull-expr resource)))

(defn pull-allowed-resources
  "Given a subject and a set of possible actions, which resources are allowed, and
  get me the documents"
  [db {:keys [subject actions purpose rules include-rules]}]
  (let [results
        (xt/q
         db
         {:find '[resource (pull action [::xt/id ::pass/pull]) purpose permission]
          :keys '[resource action purpose permission]
          :where
          (cond-> '[
                    [permission ::site/type "Permission"]
                    [action ::site/type "Action"]
                    [permission ::pass/action action]
                    [permission ::pass/purpose purpose]
                    [(contains? actions action)]

                    (allowed? permission subject action resource)]
            include-rules
            (conj '(include? subject action resource)))

          :rules (vec (concat rules include-rules))

          :in '[subject actions purpose]}

         subject actions purpose)
        pull-expr (vec (mapcat (comp ::pass/pull :action) results))]

    (->> results
         (map :resource)
         (xt/pull-many db pull-expr))))
